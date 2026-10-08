#!/usr/bin/env bash
# Check SBOMs written by run.sh. Each download-attestations.sh line must have
# produced sbom-*.json. When the line passes --platform, every package
# architecture in those files must belong to that platform. An index SBOM
# lists every architecture and fails that check.

set -euo pipefail
shopt -s nullglob

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

slug() {
  local image="$1"
  image="${image#https://}"
  image="${image#http://}"
  image="${image//\//_}"
  image="${image//:/_}"
  image="${image//@/_}"
  printf '%s\n' "$image"
}

# RPM purls use x86_64 and aarch64. Image purls use amd64 and arm64.
platform_arches() {
  case "$1" in
    linux/amd64) printf '%s\n' amd64 x86_64 ;;
    linux/arm64 | linux/arm64/*) printf '%s\n' arm64 aarch64 ;;
    linux/ppc64le) printf '%s\n' ppc64le ;;
    linux/s390x) printf '%s\n' s390x ;;
    *) return 1 ;;
  esac
}

# Unique non-noarch package architectures in an SPDX or CycloneDX file.
# An index SBOM lists every architecture. A platform SBOM lists one.
sbom_arches() {
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
    | unique
    | .[]
  ' "$1"
}

arch_allowed() {
  grep -qx -- "$1" <<<"$2"
}

failed=0
found=0
while IFS= read -r line; do
  read -r -a args <<<"${line}"
  image="${args[${#args[@]} - 1]}"
  platform=""
  i=0
  while ((i < ${#args[@]})); do
    if [[ "${args[$i]}" == "--platform" || "${args[$i]}" == "-p" ]]; then
      platform="${args[$((i + 1))]:-}"
    fi
    i=$((i + 1))
  done

  dir="./out/$(slug "${image}")"
  sboms=("${dir}"/sbom-*.json)
  found=$((found + 1))
  if ((${#sboms[@]} == 0)); then
    echo "error: no SBOM for ${image} (looked in ${dir})" >&2
    failed=1
    continue
  fi
  if [[ -z "$platform" ]]; then
    echo "ok ${image} (${#sboms[@]} SBOM(s), no --platform)"
    printf '  %s\n' "${sboms[@]##*/}"
    continue
  fi
  if ! allowed="$(platform_arches "$platform")"; then
    echo "error: unsupported platform ${platform} for ${image}" >&2
    failed=1
    continue
  fi

  for sbom in "${sboms[@]}"; do
    mapfile -t arches < <(sbom_arches "$sbom")
    if ((${#arches[@]} == 0)); then
      echo "error: ${sbom##*/} for ${image} has no package architecture; expected ${platform}" >&2
      failed=1
      continue
    fi
    bad=0
    for arch in "${arches[@]}"; do
      if ! arch_allowed "$arch" "$allowed"; then
        echo "error: ${sbom##*/} for ${image} has architecture ${arch}; expected ${platform}" >&2
        bad=1
      fi
    done
    if ((bad != 0)); then
      failed=1
      continue
    fi
    echo "ok ${image} ${platform} ${sbom##*/} (${arches[*]})"
  done
done < <(grep -E '^[[:space:]]*\./download-attestations\.sh' run.sh || true)

if ((found == 0)); then
  echo "error: no download-attestations.sh invocations in run.sh" >&2
  exit 1
fi
exit "${failed}"
