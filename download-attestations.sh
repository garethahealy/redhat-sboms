#!/usr/bin/env bash
# Download and verify in-toto attestations for a container image with cosign,
# then extract any embedded SBOMs. When those attestations contain no SPDX or
# CycloneDX document, download the Cosign SBOM attachment. See usage().

set -euo pipefail

# Keep the script's stdout. run_cli prints the command there even when the
# command's own stdout or stderr is redirected or captured.
exec 3>&1

readonly PROG_NAME="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly DEFAULT_KEY="${SCRIPT_DIR}/redhat-sigstore.pub"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

log() {
  printf '%s\n' "$*"
}

# Print a CLI command, then run it.
run_cli() {
  printf '+' >&3
  printf ' %q' "$@" >&3
  printf '\n' >&3
  "$@"
}

usage() {
  cat <<EOF
Usage: ${PROG_NAME} [options] <image>

Resolve an image tag to a digest, verify its signature, and write an SBOM.
SBOMs are written as sbom-NN-<arch>-spdx.json or
sbom-NN-<arch>-cdx-<version>.json in the output directory. Attestation
envelopes, payloads, and predicates go in att/.

The tag is resolved to a digest with oras. When --platform is set, oras
selects that platform's manifest. Referrers are listed with oras discover.
An empty referrer list is normal: registry.redhat.io publishes these objects
as Cosign tags. The image signature is verified with cosign and the public
key, unless --skip-verify-image is set. Transparency-log checks are skipped.

SBOM sources, in order. Every SPDX or CycloneDX document in the attestations
is written. The attachment is downloaded only when that count is zero.

  Attestation
    cosign download attestation (tag sha256-<digest>.att).
    A Konflux SPDX statement uses predicateType https://spdx.dev/Document
    and the predicate is the SBOM. An older OSBS attestation carries
    CycloneDX in predicate.Data.
    SPDX and CycloneDX envelopes are verified with the public key, unless
    --skip-verify-attestation is set. The script warns if at least one of
    those envelopes was checked and none verified.
    SLSA provenance (https://slsa.dev/provenance/) is stored under att/ and
    skipped. Konflux Tekton Chains signs it with a different key.
    Example:
      ${PROG_NAME} --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
      The amd64 manifest's attestations include an SPDX document, which is
      the SBOM, and SLSA provenance.
      ${PROG_NAME} registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1

  SBOM attachment
    cosign download sbom (tag sha256-<digest>.sbom).
    Used when no attestation contains an SPDX or CycloneDX document.
    The body is saved when it is SPDX or CycloneDX JSON, as sbom-00-<arch>-*.json.
    The attachment has no in-toto signature, so the script warns that it was
    saved without signature verification.

For a multi-arch image, --platform selects that architecture's manifest when
the tag is resolved, so the SBOM is the one for that architecture. Downloads
then use that digest. Because the digest is no longer an index, cosign is
retried without --platform. Without --platform, resolution stays on the tag
digest. When a single-arch image does not match --platform, resolution is
retried without it.

If the image has no attestations and no SBOM attachment, the script warns
and exits successfully.

Options:
  -o, --output-dir DIR     Directory to write artifacts
                           (default: ./out/<image-slug>)
  -p, --platform PLATFORM  Platform manifest to resolve (e.g. linux/amd64)
  -k, --key FILE           Cosign public key
                           (default: redhat-sigstore.pub next to this script)
      --skip-verify-image  Skip image signature verification
      --skip-verify-attestation
                           Skip attestation signature verification
  -h, --help               Show this help
EOF
}

require_cmds() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: ${cmd}"
  done
}

require_option_value() {
  local opt="$1"
  if [[ $# -lt 2 || -z "${2}" || "$2" == -* ]]; then
    die "${opt} requires an argument"
  fi
}

# Registry/repository of an image reference, without tag or digest.
image_repository() {
  local image="$1"
  local name="${image##*/}"

  if [[ "$image" == *@* ]]; then
    printf '%s\n' "${image%%@*}"
    return
  fi
  if [[ "$name" == *:* ]]; then
    printf '%s\n' "${image%:*}"
  else
    printf '%s\n' "$image"
  fi
}

# Output-directory slug: strip a URL scheme and replace / : @ with _.
image_slug() {
  local image="$1"
  image="${image#https://}"
  image="${image#http://}"
  image="${image//\//_}"
  image="${image//:/_}"
  image="${image//@/_}"
  printf '%s\n' "$image"
}

# Turn an in-toto predicateType URI into a filename token.
# https://spdx.dev/Document -> spdx-document
# https://slsa.dev/provenance/v0.2 -> slsa-provenance-v0.2
predicate_type_slug() {
  local ptype="${1:-}"
  local rest host uri_path first slug

  if [[ -z "$ptype" || "$ptype" == "null" ]]; then
    printf 'unknown\n'
    return
  fi

  rest="${ptype#https://}"
  rest="${rest#http://}"
  host="${rest%%/*}"
  if [[ "$rest" == */* ]]; then
    uri_path="${rest#*/}"
  else
    uri_path=""
  fi
  first="${host%%.*}"
  slug="$first"
  if [[ -n "$uri_path" ]]; then
    slug="${slug}-${uri_path}"
  fi
  slug="$(printf '%s' "$slug" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/-+/-/g; s/^-+//; s/-+$//')"
  printf '%s\n' "${slug:-unknown}"
}

# Resolve a tag or digest to image@sha256:...
# When platform is set, oras --platform selects that manifest. An image whose
# platform does not match is resolved again without --platform.
resolve_digest_ref() {
  local image="$1"
  local platform="${2:-}"
  local out err_file ref digest repo rc
  local -a fetch_cmd discover_cmd

  if [[ "$image" == *@sha256:* && -z "$platform" ]]; then
    printf '%s\n' "$image"
    return 0
  fi

  err_file="$(mktemp)"
  fetch_cmd=(oras manifest fetch --descriptor)
  if [[ -n "$platform" ]]; then
    fetch_cmd+=(--platform "$platform")
  fi
  rc=0
  out="$(run_cli "${fetch_cmd[@]}" "$image" 2>"$err_file")" || rc=$?
  if ((rc == 0)) && jq -e . >/dev/null 2>&1 <<<"$out"; then
    digest="$(jq -r '.digest // empty' <<<"$out")"
    if [[ "$digest" == sha256:* ]]; then
      rm -f "$err_file"
      repo="$(image_repository "$image")"
      printf '%s@%s\n' "$repo" "$digest"
      return 0
    fi
  fi
  if [[ -n "$platform" ]] && grep -q 'does not match target platform' "$err_file"; then
    warn "image platform does not match ${platform}; resolving without --platform"
    rm -f "$err_file"
    resolve_digest_ref "$image"
    return
  fi

  # Older oras JSON from discover has no subject reference; the tree view prints it first.
  discover_cmd=(oras discover --format tree)
  if [[ -n "$platform" ]]; then
    discover_cmd+=(--platform "$platform")
  fi
  rc=0
  out="$(run_cli "${discover_cmd[@]}" "$image" 2>"$err_file")" || rc=$?
  if ((rc != 0)); then
    if [[ -n "$platform" ]] && grep -q 'does not match target platform' "$err_file"; then
      warn "image platform does not match ${platform}; resolving without --platform"
      rm -f "$err_file"
      resolve_digest_ref "$image"
      return
    fi
    rm -f "$err_file"
    die "failed to resolve digest for ${image}"
  fi
  rm -f "$err_file"

  ref="$(printf '%s\n' "$out" | awk '/@sha256:/{gsub(/^[[:space:]]+/, ""); print; exit}')"
  if [[ -z "$ref" ]]; then
    printf '%s\n' "$out" >&2
    die "did not return a digest reference for ${image}"
  fi
  printf '%s\n' "$ref"
}

# List OCI referrers for the resolved digest. An empty list is normal on
# registry.redhat.io. Attestations and SBOM attachments are read from the
# Cosign tags below; this listing does not select them.
discover_referrers() {
  local digest_ref="$1"

  log "discovering referrers for ${digest_ref}"
  run_cli oras discover --format tree "$digest_ref"
}

# Verify the image signature with the public key. Transparency-log checks
# are skipped.
verify_image() {
  local digest_ref="$1"
  local key="$2"

  log "verifying image ${digest_ref} with ${key}"
  run_cli cosign verify --key "$key" --insecure-ignore-tlog=true "$digest_ref" >/dev/null
}

# Run cosign with optional --platform. After oras --platform, the digest is
# that platform's manifest, so it is not an index. Cosign then reports that
# and the command is retried without --platform. The same retry covers an
# image that was already single-arch.
run_cosign_with_platform() {
  local platform="$1"
  local out_file="$2"
  local digest_ref="$3"
  shift 3
  local err
  local rc=0
  local -a cmd

  cmd=(cosign "$@")
  if [[ -z "$platform" ]]; then
    err="$(run_cli "${cmd[@]}" "$digest_ref" 2>&1 >"$out_file")" || rc=$?
  else
    err="$(run_cli "${cmd[@]}" --platform "$platform" "$digest_ref" 2>&1 >"$out_file")" || rc=$?
    if ((rc != 0)) && [[ "$err" == *"not a multiarch image"* ]]; then
      log "digest is not a multi-arch index; retrying without --platform ${platform}"
      : >"$out_file"
      rc=0
      err="$(run_cli "${cmd[@]}" "$digest_ref" 2>&1 >"$out_file")" || rc=$?
    fi
  fi

  COSIGN_ERR="$err"
  return "$rc"
}

# Cosign exits non-zero when the attestation tag is absent. An empty file
# plus one of these messages is "nothing to download", not a failed download.
missing_attestations() {
  local err="$1"
  local att_file="$2"

  [[ -s "$att_file" ]] && return 1
  [[ "$err" == *[Aa]ttestation* || "$err" == *MANIFEST_UNKNOWN* || "$err" == *manifest\ unknown* ]]
}

# Cosign exits non-zero when the .sbom tag is absent.
missing_sbom() {
  local err="$1"
  local sbom_file="$2"
  local err_lc

  [[ -s "$sbom_file" ]] && return 1
  err_lc="$(printf '%s' "$err" | tr '[:upper:]' '[:lower:]')"
  [[ "$err_lc" == *no\ sbom* || "$err_lc" == *manifest_unknown* || "$err_lc" == *manifest\ unknown* ]]
}

# Predicate type from a Cosign DSSE envelope (JSONL line).
attestation_predicate_type() {
  local line="$1"
  local payload ptype

  payload="$(jq -r '.payload // .dsseEnvelope.payload // empty' <<<"$line")"
  if [[ -z "$payload" ]]; then
    printf 'unknown\n'
    return
  fi
  ptype="$(printf '%s' "$payload" | base64 -d 2>/dev/null | jq -r '.predicateType // "unknown"')" || ptype="unknown"
  printf '%s\n' "${ptype:-unknown}"
}

# True for https://slsa.dev/provenance/*. Konflux Tekton Chains signs these
# with a different key, so verification is skipped.
is_slsa_provenance() {
  [[ "${1:-}" == https://slsa.dev/provenance/* ]]
}

# Verify one downloaded DSSE envelope with cosign (signature only, not claims).
# Cosign still requires --type when --check-claims=false.
verify_dsse_envelope() {
  local envelope_file="$1"
  local key="$2"
  local t

  for t in spdxjson cyclonedx custom; do
    if run_cli cosign verify-blob-attestation \
      --key "$key" \
      --signature "$envelope_file" \
      --type "$t" \
      --check-claims=false \
      --insecure-ignore-tlog=true \
      /dev/null >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

# Verify SPDX and CycloneDX envelopes in attestations.jsonl with the public
# key. SLSA provenance is stored and skipped. Warn when at least one envelope
# was checked and none verified, then continue. An all-SLSA file warns and
# returns success.
verify_attestations() {
  local key="$1"
  local att_file="$2"
  local line index=0 tmp ptype padded
  local verified=0 skipped=0 attempted=0

  tmp="$(mktemp)"

  log "verifying ${att_file} with ${key}"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    padded="$(printf '%02d' "$index")"
    ptype="$(attestation_predicate_type "$line")"
    if is_slsa_provenance "$ptype"; then
      log "skipping verification of attestation ${padded} (${ptype})"
      skipped=$((skipped + 1))
      index=$((index + 1))
      continue
    fi
    attempted=$((attempted + 1))
    printf '%s\n' "$line" >"$tmp"
    log "verifying attestation ${padded} (${ptype})"
    if verify_dsse_envelope "$tmp" "$key"; then
      verified=$((verified + 1))
    fi
    index=$((index + 1))
  done <"$att_file"
  rm -f "$tmp"

  ((index > 0)) || die "no attestations to verify in ${att_file}"
  if ((attempted == 0)); then
    warn "no attestations verified with ${key}; skipped ${skipped} SLSA provenance envelope(s)"
    return 0
  fi
  if ((verified == 0)); then
    warn "none of the attestations verified with ${key}"
  fi
}

# Attestation source: cosign download attestation (tag sha256-<digest>.att).
# One DSSE envelope per line in the output file. A missing tag leaves that
# file empty and returns success. Other cosign errors are returned.
download_attestations() {
  local digest_ref="$1"
  local platform="$2"
  local att_file="$3"
  local rc=0

  log "downloading attestations for ${digest_ref}"
  run_cosign_with_platform "$platform" "$att_file" "$digest_ref" download attestation || rc=$?
  if ((rc == 0)); then
    return 0
  fi
  if missing_attestations "$COSIGN_ERR" "$att_file"; then
    : >"$att_file"
    return 0
  fi
  printf '%s\n' "$COSIGN_ERR" >&2
  return "$rc"
}

# SBOM attachment source: cosign download sbom (tag sha256-<digest>.sbom).
# Called when SBOM_COUNT is still zero after attestation extraction.
# SPDX or CycloneDX JSON is written as sbom-00-<arch>-*.json. Any other body
# is written as sbom-00-unknown.txt. A missing tag warns and returns success.
# The attachment is not an in-toto envelope, so it is saved without signature
# verification.
download_sbom_attachment() {
  local digest_ref="$1"
  local platform="$2"
  local dest_dir="$3"
  local tmp sbom_file rc=0

  tmp="$(mktemp)"
  log "no SBOM in attestations; downloading SBOM attachment for ${digest_ref}"
  run_cosign_with_platform "$platform" "$tmp" "$digest_ref" download sbom || rc=$?
  if ((rc != 0)); then
    if missing_sbom "$COSIGN_ERR" "$tmp"; then
      warn "no SBOM attachment found for ${IMAGE}"
      rm -f "$tmp"
      return 0
    fi
    printf '%s\n' "$COSIGN_ERR" >&2
    rm -f "$tmp"
    return "$rc"
  fi

  if [[ ! -s "$tmp" ]] || ! is_sbom_document <"$tmp"; then
    cp "$tmp" "${dest_dir}/sbom-00-unknown.txt"
    warn "SBOM attachment is not CycloneDX or SPDX JSON; wrote ${dest_dir}/sbom-00-unknown.txt"
    rm -f "$tmp"
    return 0
  fi

  sbom_file="${dest_dir}/$(sbom_filename 0 <"$tmp")"
  jq . <"$tmp" >"$sbom_file"
  rm -f "$tmp"
  SBOM_COUNT=$((SBOM_COUNT + 1))
  warn "SBOM attachment is not signed as an in-toto attestation; saved without signature verification"
  log "wrote ${sbom_file}"
}

# Majority package architecture from CycloneDX purls (arch=) or SPDX
# externalRefs. noarch is ignored. This value is the <arch> in SBOM filenames.
sbom_arch() {
  jq -r '
    [
      (
        (.components // [])[]
        | (.purl // "")
        | capture("arch=(?<a>[^&]+)")?
        | .a
      ),
      (
        (.packages // [])[]
        | (.externalRefs // [])[]
        | select(.referenceType == "purl")
        | (.referenceLocator // "")
        | capture("arch=(?<a>[^&]+)")?
        | .a
      )
    ]
    | map(select(. != null and . != "noarch"))
    | group_by(.)
    | map({arch: .[0], n: length})
    | (max_by(.n) | .arch) // "unknown"
  '
}

# CycloneDX JSON or SPDX JSON. Reads the document on stdin.
is_sbom_document() {
  jq -e '.bomFormat == "CycloneDX" or (.spdxVersion | type == "string")' >/dev/null 2>&1
}

# Reads the SBOM JSON on stdin. index is the filename sequence number.
sbom_filename() {
  local index="$1"
  local sbom format arch version

  sbom="$(cat)"
  format="$(jq -r '.bomFormat // .spdxVersion // empty' <<<"$sbom")"
  arch="$(sbom_arch <<<"$sbom")"

  case "$format" in
    CycloneDX)
      version="$(jq -r '.specVersion // "unknown"' <<<"$sbom")"
      printf 'sbom-%02d-%s-cdx-%s.json\n' "$index" "$arch" "$version"
      ;;
    SPDX-*)
      printf 'sbom-%02d-%s-spdx.json\n' "$index" "$arch"
      ;;
    *)
      printf 'sbom-%02d-%s.json\n' "$index" "$arch"
      ;;
  esac
}

write_json_or_raw() {
  local dest="$1"
  local content="$2"

  if jq -e . >/dev/null 2>&1 <<<"$content"; then
    jq . <<<"$content" >"$dest"
    return 0
  fi

  printf '%s\n' "$content" >"${dest%.json}.txt"
  return 1
}

# Write one DSSE envelope, its statement, and its predicate under att/.
# When predicate.Data or predicate.data is non-empty, that value is checked
# as the SBOM. Otherwise the predicate itself is checked. An SPDX or
# CycloneDX document is written at the output root and increments SBOM_COUNT.
# Other Data is stored as att/predicate-NN-data.txt.
extract_one_attestation() {
  local dest_dir="$1"
  local att_dir="$2"
  local index="$3"
  local line="$4"
  local padded envelope_file payload_file predicate_file sbom_file
  local payload statement predicate data sbom type_slug

  padded="$(printf '%02d' "$index")"
  envelope_file="${att_dir}/attestation-${padded}.json"

  if write_json_or_raw "$envelope_file" "$line"; then
    log "wrote ${envelope_file}"
  else
    warn "attestation ${padded} envelope is not valid JSON; wrote ${envelope_file%.json}.txt"
    return 0
  fi

  payload="$(jq -r '.payload // .dsseEnvelope.payload // empty' <<<"$line")"
  if [[ -z "$payload" ]]; then
    warn "attestation ${padded} has no payload"
    return 0
  fi

  if ! statement="$(printf '%s' "$payload" | base64 -d 2>/dev/null)"; then
    printf '%s\n' "$payload" >"${att_dir}/payload-${padded}-unknown.b64"
    warn "attestation ${padded} payload is not valid base64; wrote payload-${padded}-unknown.b64"
    return 0
  fi

  type_slug="unknown"
  if jq -e . >/dev/null 2>&1 <<<"$statement"; then
    type_slug="$(predicate_type_slug "$(jq -r '.predicateType // empty' <<<"$statement")")"
  fi
  payload_file="${att_dir}/payload-${padded}-${type_slug}.json"

  if write_json_or_raw "$payload_file" "$statement"; then
    log "wrote ${payload_file}"
  else
    warn "attestation ${padded} payload is not valid JSON; wrote ${payload_file%.json}.txt"
    return 0
  fi

  predicate="$(jq -c '.predicate // empty' <<<"$statement")"
  if [[ -z "$predicate" || "$predicate" == "null" ]]; then
    warn "attestation ${padded} has no predicate"
    return 0
  fi

  predicate_file="${att_dir}/predicate-${padded}.json"
  if write_json_or_raw "$predicate_file" "$predicate"; then
    log "wrote ${predicate_file}"
  else
    warn "attestation ${padded} predicate is not valid JSON; wrote ${predicate_file%.json}.txt"
    return 0
  fi

  data="$(jq -r '.Data // .data // empty' <<<"$predicate")"
  sbom="$predicate"
  if [[ -n "$data" ]]; then
    sbom="$data"
  fi

  if is_sbom_document <<<"$sbom"; then
    sbom_file="${dest_dir}/$(sbom_filename "$index" <<<"$sbom")"
    jq . <<<"$sbom" >"$sbom_file"
    log "wrote ${sbom_file}"
    SBOM_COUNT=$((SBOM_COUNT + 1))
  elif [[ -n "$data" ]]; then
    printf '%s\n' "$data" >"${att_dir}/predicate-${padded}-data.txt"
    log "wrote ${att_dir}/predicate-${padded}-data.txt"
  fi
}

# Walk attestations.jsonl. Each non-empty line is one envelope. SBOM_COUNT
# is the number of SPDX or CycloneDX documents written from those lines.
extract_attestations() {
  local dest_dir="$1"
  local att_dir="$2"
  local att_file="$3"
  local index=0
  local line

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    extract_one_attestation "$dest_dir" "$att_dir" "$index" "$line"
    index=$((index + 1))
  done <"$att_file"
}

parse_args() {
  local opt
  IMAGE=""
  OUTPUT_DIR=""
  PLATFORM=""
  KEY=""
  SKIP_VERIFY_IMAGE=0
  SKIP_VERIFY_ATTESTATION=0

  while [[ $# -gt 0 ]]; do
    opt="$1"
    case "$opt" in
      -h | --help)
        usage
        exit 0
        ;;
      -o | --output-dir)
        require_option_value "$opt" "${2:-}"
        OUTPUT_DIR="$2"
        shift 2
        ;;
      -p | --platform)
        require_option_value "$opt" "${2:-}"
        PLATFORM="$2"
        shift 2
        ;;
      -k | --key)
        require_option_value "$opt" "${2:-}"
        KEY="$2"
        shift 2
        ;;
      --skip-verify-image)
        SKIP_VERIFY_IMAGE=1
        shift
        ;;
      --skip-verify-attestation)
        SKIP_VERIFY_ATTESTATION=1
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        printf 'error: unknown option: %s\n' "$opt" >&2
        usage >&2
        exit 1
        ;;
      *)
        if [[ -n "$IMAGE" ]]; then
          printf 'error: unexpected extra argument: %s\n' "$opt" >&2
          usage >&2
          exit 1
        fi
        IMAGE="$opt"
        shift
        ;;
    esac
  done

  if [[ $# -gt 0 ]]; then
    if [[ -n "$IMAGE" ]]; then
      printf 'error: unexpected extra argument: %s\n' "$1" >&2
      usage >&2
      exit 1
    fi
    IMAGE="$1"
    shift
  fi
  if [[ $# -gt 0 ]]; then
    printf 'error: unexpected extra argument: %s\n' "$1" >&2
    usage >&2
    exit 1
  fi
}

main() {
  local digest_ref att_dir att_file count
  SBOM_COUNT=0

  parse_args "$@"

  if [[ -z "$IMAGE" ]]; then
    usage >&2
    exit 1
  fi

  require_cmds cosign jq oras base64

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="./out/$(image_slug "$IMAGE")"
  fi

  if [[ -z "$KEY" ]]; then
    KEY="$DEFAULT_KEY"
  fi
  if [[ ! -f "$KEY" ]]; then
    die "public key not found: ${KEY}"
  fi

  att_dir="${OUTPUT_DIR}/att"
  mkdir -p "$att_dir"

  log "resolving digest for ${IMAGE}"
  digest_ref="$(resolve_digest_ref "$IMAGE" "$PLATFORM")"
  log "using ${digest_ref}"

  discover_referrers "$digest_ref"
  if [[ "$SKIP_VERIFY_IMAGE" -eq 1 ]]; then
    log "skipping image signature verification"
  else
    verify_image "$digest_ref" "$KEY"
  fi

  att_file="${att_dir}/attestations.jsonl"
  download_attestations "$digest_ref" "$PLATFORM" "$att_file"

  if [[ -s "$att_file" ]]; then
    count="$(grep -c . "$att_file" || true)"
    log "wrote ${att_file} (${count} attestation(s))"
    if [[ "$SKIP_VERIFY_ATTESTATION" -eq 1 ]]; then
      log "skipping attestation verification"
    else
      verify_attestations "$KEY" "$att_file"
    fi
    extract_attestations "$OUTPUT_DIR" "$att_dir" "$att_file"
  else
    warn "no attestations found for ${IMAGE}"
  fi

  if ((SBOM_COUNT == 0)); then
    download_sbom_attachment "$digest_ref" "$PLATFORM" "$OUTPUT_DIR"
  fi
  printf '\n'
}

main "$@"
