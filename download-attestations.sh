#!/usr/bin/env bash
# Download and verify in-toto attestations for a container image with cosign,
# then extract any embedded SBOMs. Konflux images typically attach SPDX (and
# SLSA provenance). Older OSBS images wrap CycloneDX in predicate.Data.

set -euo pipefail

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

usage() {
  cat <<EOF
Usage: ${PROG_NAME} [options] <image>

Download and verify attestations for a container image, then write them under
the output directory. Envelopes, payloads, and predicates go in att/. Extracted
SBOMs are written at the output directory root.

Attestations.jsonl is verified with cosign and Red Hat's Sigstore public key
(redhat-sigstore.pub). SLSA provenance envelopes are kept but not verified;
those are signed by Konflux Tekton Chains with a different key.

Examples:
  ${PROG_NAME} --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
  ${PROG_NAME} registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1

The image tag is resolved to a digest with oras. Referrers are listed with
oras discover, then the image signature is verified with cosign before
attestations are downloaded.

For multi-arch images, --platform selects that arch so the SBOM includes
packages. Without it, a multi-arch tag yields the index SBOM (images only).

Options:
  -o, --output-dir DIR     Directory to write artifacts
                           (default: ./out/<image-slug>)
  -p, --platform PLATFORM  Select one platform from a multi-arch index
                           (e.g. linux/amd64)
  -k, --key FILE           Cosign public key
                           (default: redhat-sigstore.pub next to this script)
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

# Resolve a tag (or digest) to image@sha256:...
# Do not pass --platform here: that pins a child manifest, and cosign then
# errors with "specified reference is not a multiarch image".
resolve_digest_ref() {
  local image="$1"
  local out ref digest repo

  if [[ "$image" == *@sha256:* ]]; then
    printf '%s\n' "$image"
    return 0
  fi

  if out="$(oras manifest fetch --descriptor "$image" 2>/dev/null)" && jq -e . >/dev/null 2>&1 <<<"$out"; then
    digest="$(jq -r '.digest // empty' <<<"$out")"
    if [[ "$digest" == sha256:* ]]; then
      repo="$(image_repository "$image")"
      printf '%s@%s\n' "$repo" "$digest"
      return 0
    fi
  fi

  # Older oras JSON from discover has no subject reference; the tree view prints it first.
  if ! out="$(oras discover --format tree "$image")"; then
    die "failed to resolve digest for ${image}"
  fi

  ref="$(printf '%s\n' "$out" | awk '/@sha256:/{gsub(/^[[:space:]]+/, ""); print; exit}')"
  if [[ -z "$ref" ]]; then
    printf '%s\n' "$out" >&2
    die "did not return a digest reference for ${image}"
  fi
  printf '%s\n' "$ref"
}

discover_referrers() {
  local digest_ref="$1"

  log "discovering referrers for ${digest_ref}"
  oras discover --format tree "$digest_ref"
}

verify_image() {
  local digest_ref="$1"
  local key="$2"

  log "verifying image ${digest_ref} with ${key}"
  cosign verify --key "$key" --insecure-ignore-tlog=true "$digest_ref" >/dev/null
}

# Run cosign with optional --platform. If the digest is already a single-arch
# image, retry without --platform.
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
    "${cmd[@]}" "$digest_ref" >"$out_file"
    return 0
  fi

  err="$("${cmd[@]}" --platform "$platform" "$digest_ref" 2>&1 >"$out_file")" || rc=$?
  if ((rc == 0)); then
    return 0
  fi
  if [[ "$err" == *"not a multiarch image"* ]]; then
    warn "image is not a multi-arch index; retrying without --platform ${platform}"
    : >"$out_file"
    "${cmd[@]}" "$digest_ref" >"$out_file"
    return 0
  fi

  printf '%s\n' "$err" >&2
  return "$rc"
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

# Konflux SLSA provenance is signed with a per-cluster ECDSA key, not
# redhat-sigstore.pub.
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
    if cosign verify-blob-attestation \
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
    else
      warn "attestation ${padded} (${ptype}) did not verify with this key"
    fi
    index=$((index + 1))
  done <"$att_file"
  rm -f "$tmp"

  ((index > 0)) || die "no attestations to verify in ${att_file}"
  if ((attempted == 0)); then
    warn "no attestations verified with ${key}; skipped ${skipped} SLSA provenance envelope(s)"
    return 0
  fi
  ((verified > 0)) || die "none of the attestations verified with ${key}"
}

download_attestations() {
  local digest_ref="$1"
  local platform="$2"
  local att_file="$3"

  log "downloading attestations for ${digest_ref}"
  run_cosign_with_platform "$platform" "$att_file" "$digest_ref" download attestation
}

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

sbom_filename() {
  local sbom="$1"
  local index="$2"
  local format arch version

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

  if jq -e '.bomFormat == "CycloneDX" or (.spdxVersion | type == "string")' >/dev/null 2>&1 <<<"$sbom"; then
    sbom_file="${dest_dir}/$(sbom_filename "$sbom" "$index")"
    jq . <<<"$sbom" >"$sbom_file"
    log "wrote ${sbom_file}"
  elif [[ -n "$data" ]]; then
    printf '%s\n' "$data" >"${att_dir}/predicate-${padded}-data.txt"
    log "wrote ${att_dir}/predicate-${padded}-data.txt"
  fi
}

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
  digest_ref="$(resolve_digest_ref "$IMAGE")"
  log "using ${digest_ref}"

  discover_referrers "$digest_ref"
  verify_image "$digest_ref" "$KEY"

  att_file="${att_dir}/attestations.jsonl"
  download_attestations "$digest_ref" "$PLATFORM" "$att_file"

  if [[ ! -s "$att_file" ]]; then
    die "no attestations written for ${IMAGE}"
  fi

  count="$(grep -c . "$att_file" || true)"
  log "wrote ${att_file} (${count} attestation(s))"

  verify_attestations "$KEY" "$att_file"

  extract_attestations "$OUTPUT_DIR" "$att_dir" "$att_file"
  printf '\n'
}

main "$@"
