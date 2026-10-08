#!/usr/bin/env bash
# Read an oc-mirror v2 dry-run mapping.txt and run download-attestations.sh
# for each selected source image. That script tries an in-toto attestation
# SBOM, then a Cosign SBOM attachment. See download-attestations.sh --help.

set -euo pipefail

# Keep the script's stdout. run_cli prints the command there even when the
# command's own stdout or stderr is redirected or captured.
exec 3>&1

readonly PROG_NAME="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly DOWNLOAD_SCRIPT="${SCRIPT_DIR}/download-attestations.sh"
readonly DEFAULT_MAPPING="oc-mirror-data/working-dir/dry-run/mapping.txt"
readonly DEFAULT_SOURCES=(registry.redhat.io quay.io)

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
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
Usage: ${PROG_NAME} [options] [mapping.txt]

Read an oc-mirror v2 mapping.txt and run download-attestations.sh for each
selected source (the reference to the left of '='). The destination on the
right of '=' is ignored.

download-attestations.sh tries two SBOM sources for each image, in order.
Every SPDX or CycloneDX document in the attestations is written. The
attachment is downloaded only when that count is zero.

  Attestation
    cosign download attestation (tag sha256-<digest>.att).
    A Konflux SPDX statement uses predicateType https://spdx.dev/Document
    and the predicate is the SBOM. An older OSBS attestation carries
    CycloneDX in predicate.Data.
    SPDX and CycloneDX envelopes are verified with the public key, unless
    --skip-verify-attestation is set. The child script warns if at least one
    of those envelopes was checked and none verified. SLSA provenance
    (https://slsa.dev/provenance/) is stored under
    att/ and skipped. Konflux Tekton Chains signs it with a different key.

  SBOM attachment
    cosign download sbom (tag sha256-<digest>.sbom).
    The body is saved when it is SPDX or CycloneDX JSON, as
    sbom-00-<arch>-*.json. The attachment has no in-toto signature, so the
    child script warns that it was saved without signature verification.

--platform is forwarded. For a multi-arch image it selects that
architecture's manifest when the tag is resolved, so the SBOM is the one
for that architecture. Downloads then use that digest. Because the digest
is no longer an index, the child script retries cosign without --platform.
Without --platform, resolution stays on the tag digest. When a single-arch
image does not match --platform, resolution is retried without it.

The tag is resolved to a digest with oras. When --platform is set, that
platform's manifest is selected. An empty oras discover list is normal.
The image signature is verified with the public key, unless
--skip-verify-image is set. Transparency-log checks are skipped. If an
image has no attestations and no SBOM attachment, the child script warns
and exits successfully, which this script treats as success.

By default the source registries are registry.redhat.io and quay.io. Pass
--source more than once to replace that set. The default mapping file is
oc-mirror-data/working-dir/dry-run/mapping.txt.

Blank lines and lines starting with # are skipped. A line without '=' is
an error.

A source of name:tag@sha256:digest is one platform of a manifest list. When
the same name:tag is also listed, that platform line is skipped so one image
set entry stays one download. When the name:tag line is absent, the platform
line is kept as repository@sha256:digest (the tag is removed). Duplicate
references are skipped.

Each image is still downloaded when an earlier image fails. This script
exits non-zero when any download fails.

Examples:
  ${PROG_NAME} oc-mirror-data/working-dir/dry-run/mapping.txt
  ${PROG_NAME} --source registry.redhat.io --source quay.io mapping.txt
  ${PROG_NAME} --platform linux/amd64 --key /home/runner/redhat-sigstore.pub mapping.txt

Options:
  -s, --source REGISTRY    Source registry hostname to include (repeatable).
                           Replaces the default set when given.
  -p, --platform PLATFORM  Platform forwarded when resolving the image
  -k, --key FILE           Cosign public key forwarded to download-attestations.sh
      --skip-verify-image  Skip image signature verification
      --skip-verify-attestation
                           Skip attestation signature verification
  -n, --print              Print the image references and do not download
  -h, --help               Show this help
EOF
}

require_option_value() {
  local opt="$1"
  if [[ $# -lt 2 || -z "${2}" || "$2" == -* ]]; then
    die "${opt} requires an argument"
  fi
}

# Hostname of a docker:// reference, without the repository path.
source_host() {
  local raw="$1"
  raw="${raw#docker://}"
  printf '%s\n' "${raw%%/*}"
}

# True when host is one of the registries selected by --source, or the
# default set registry.redhat.io and quay.io.
source_selected() {
  local host="$1"
  local registry
  for registry in "${sources[@]}"; do
    [[ "$host" == "$registry" ]] && return 0
  done
  return 1
}

# docker://registry.redhat.io/ubi9/ubi:latest@sha256:abc
#   -> registry.redhat.io/ubi9/ubi@sha256:abc
# docker://quay.io/org/image:tag
#   -> quay.io/org/image:tag
source_image_ref() {
  local raw="$1"
  local repo digest

  raw="${raw#docker://}"
  if [[ "$raw" == *@sha256:* ]]; then
    repo="${raw%%@*}"
    digest="${raw#*@}"
    repo="${repo%:*}"
    printf '%s@%s\n' "$repo" "$digest"
    return
  fi
  printf '%s\n' "$raw"
}

MAPPING=""
PLATFORM=""
KEY=""
SKIP_VERIFY_IMAGE=0
SKIP_VERIFY_ATTESTATION=0
PRINT_ONLY=0
declare -a sources=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    -n | --print)
      PRINT_ONLY=1
      shift
      ;;
    -s | --source)
      require_option_value "$@"
      registry="${2#docker://}"
      registry="${registry%%/*}"
      sources+=("$registry")
      shift 2
      ;;
    -p | --platform)
      require_option_value "$@"
      PLATFORM="$2"
      shift 2
      ;;
    -k | --key)
      require_option_value "$@"
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
      die "unknown option: $1"
      ;;
    *)
      if [[ -n "$MAPPING" ]]; then
        die "unexpected extra argument: $1"
      fi
      MAPPING="$1"
      shift
      ;;
  esac
done

if [[ $# -gt 0 ]]; then
  die "unexpected extra argument: $1"
fi

if [[ ${#sources[@]} -eq 0 ]]; then
  sources=("${DEFAULT_SOURCES[@]}")
fi

if [[ -z "$MAPPING" ]]; then
  MAPPING="$DEFAULT_MAPPING"
fi
if [[ ! -f "$MAPPING" ]]; then
  die "mapping file not found: ${MAPPING}"
fi
if [[ "$PRINT_ONLY" -eq 0 && ! -x "$DOWNLOAD_SCRIPT" ]]; then
  die "download script not executable: ${DOWNLOAD_SCRIPT}"
fi

declare -a raw_sources=()
parents=" "

while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || die "mapping line has no '=': ${line}"

  source="${line%%=*}"
  source_selected "$(source_host "$source")" || continue
  raw_sources+=("$source")

  # name:tag, with no digest, is the image itself. A later
  # name:tag@sha256:digest line for this same reference is one platform of
  # that manifest list and is skipped.
  if [[ "${source#docker://}" != *@sha256:* ]]; then
    parents+="${source#docker://} "
  fi
done <"$MAPPING"

declare -a images=()
seen=" "

for source in "${raw_sources[@]}"; do
  bare="${source#docker://}"
  # Platform line whose name:tag parent was also listed. Skip it.
  # A platform line with no parent is kept; source_image_ref drops the tag
  # and leaves repository@sha256:digest.
  if [[ "$bare" == *:*@sha256:* ]]; then
    parent="${bare%%@*}"
    [[ "$parents" == *" ${parent} "* ]] && continue
  fi

  ref="$(source_image_ref "$source")"
  [[ "$seen" == *" ${ref} "* ]] && continue
  seen+="${ref} "
  images+=("$ref")
done

if [[ ${#images[@]} -eq 0 ]]; then
  die "no sources in ${MAPPING} for: ${sources[*]}"
fi

log "found ${#images[@]} source image(s) in ${MAPPING}"

if [[ "$PRINT_ONLY" -eq 1 ]]; then
  printf '%s\n' "${images[@]}"
  exit 0
fi

# Forward --platform, --key, --skip-verify-image, and --skip-verify-attestation.
# download-attestations.sh tries the attestation SBOM, then the Cosign SBOM
# attachment. Keep going after a failure so one image does not hide the rest.
failed=0
for ref in "${images[@]}"; do
  args=("$DOWNLOAD_SCRIPT")
  if [[ -n "$PLATFORM" ]]; then
    args+=(--platform "$PLATFORM")
  fi
  if [[ -n "$KEY" ]]; then
    args+=(--key "$KEY")
  fi
  if [[ "$SKIP_VERIFY_IMAGE" -eq 1 ]]; then
    args+=(--skip-verify-image)
  fi
  if [[ "$SKIP_VERIFY_ATTESTATION" -eq 1 ]]; then
    args+=(--skip-verify-attestation)
  fi
  args+=("$ref")

  log "downloading ${ref}"
  if ! run_cli "${args[@]}"; then
    printf 'error: download failed for %s\n' "$ref" >&2
    failed=$((failed + 1))
  fi
done

if [[ "$failed" -gt 0 ]]; then
  die "${failed} download(s) failed"
fi
