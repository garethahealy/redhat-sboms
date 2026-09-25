#!/usr/bin/env bash
# Read an oc-mirror v2 dry-run mapping.txt and download attestations for each
# selected source image. Defaults to registry.redhat.io and quay.io.

set -euo pipefail

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

usage() {
  cat <<EOF
Usage: ${PROG_NAME} [options] [mapping.txt]

Parse an oc-mirror v2 mapping.txt and run download-attestations.sh for each
selected source (the reference to the left of '=').

By default the source registries are registry.redhat.io and quay.io. Pass
--source more than once to use a different set. The destination on the right
of '=' is ignored.

A source of name:tag@sha256:digest is a platform manifest from a multi-arch
image. When the same name:tag is also listed, that platform line is skipped so
one image set entry stays one download. Pass --platform to select an
architecture of that image.

Examples:
  ${PROG_NAME} oc-mirror-data/working-dir/dry-run/mapping.txt
  ${PROG_NAME} --source registry.redhat.io --source quay.io mapping.txt
  ${PROG_NAME} --platform linux/amd64 --key /home/runner/redhat-sigstore.pub mapping.txt

Options:
  -s, --source REGISTRY    Source registry hostname to include (repeatable).
                           Replaces the default set when given.
  -p, --platform PLATFORM  Platform forwarded to download-attestations.sh
  -k, --key FILE           Cosign public key forwarded to download-attestations.sh
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

  # name:tag, with no digest, is the image itself. Platform lines hang off it.
  if [[ "${source#docker://}" != *@sha256:* ]]; then
    parents+="${source#docker://} "
  fi
done <"$MAPPING"

declare -a images=()
seen=" "

for source in "${raw_sources[@]}"; do
  bare="${source#docker://}"
  # name:tag@sha256:digest is one platform of a manifest list, not another image.
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

failed=0
for ref in "${images[@]}"; do
  args=("$DOWNLOAD_SCRIPT")
  if [[ -n "$PLATFORM" ]]; then
    args+=(--platform "$PLATFORM")
  fi
  if [[ -n "$KEY" ]]; then
    args+=(--key "$KEY")
  fi
  args+=("$ref")

  log "downloading attestations for ${ref}"
  if ! "${args[@]}"; then
    printf 'error: download failed for %s\n' "$ref" >&2
    failed=$((failed + 1))
  fi
done

if [[ "$failed" -gt 0 ]]; then
  die "${failed} download(s) failed"
fi
