# redhat-sboms

Download and verify Sigstore attestations, then extract SBOMs for Red Hat container images.

## Prerequisites

- [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
- [`oras`](https://oras.land/docs/installation/)
- [`jq`](https://jqlang.github.io/jq/)
- `base64`

Images on `registry.redhat.io` need a Red Hat registry login.

## Setup

Download Red Hat release key 3 next to the script:

```bash
wget -O redhat-sigstore.pub https://security.access.redhat.com/data/63405576.txt
```

## Usage

```bash
./download-attestations.sh --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
./download-attestations.sh registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1
```

The first image is multi-arch and publishes its SBOM as a Cosign attachment. The second is single-arch and publishes its SBOM as an SPDX attestation.

`./download-attestations.sh --help` lists `--output-dir`, `--platform`, and `--key`.

`download-from-mapping.sh` runs that script for each selected source in an oc-mirror v2 `mapping.txt`. Both methods below apply to every image. `--platform` and `--key` are forwarded to both downloads.

```bash
./download-from-mapping.sh --platform linux/amd64 oc-mirror-data/working-dir/dry-run/mapping.txt
```

`./download-from-mapping.sh --help` lists `--source` and `--print`.

## Methods

The tag is resolved to a digest with `oras`. `--platform` is applied when an attestation or SBOM attachment is downloaded, so resolution stays on the index digest. Referrers are listed with `oras discover`. An empty referrer list is normal on `registry.redhat.io`, which publishes these objects as Cosign tags. The image signature is then verified with `cosign` and `redhat-sigstore.pub`. Transparency-log checks are skipped.

Every SPDX or CycloneDX document in the attestations is written. The attachment is downloaded only when that count is zero.

### Attestation

`cosign download attestation` reads the tag `sha256-<digest>.att`.

- A Konflux SPDX statement uses predicate type `https://spdx.dev/Document`. The predicate is the SBOM.
- An older OSBS attestation carries CycloneDX in `predicate.Data`.
- SPDX and CycloneDX envelopes are verified with `redhat-sigstore.pub`. The script exits if at least one of those envelopes was checked and none verified.
- SLSA provenance (`https://slsa.dev/provenance/`) is stored under `att/` and skipped. Konflux Tekton Chains signs it with a different key.

Example: `registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1`

### SBOM attachment

`cosign download sbom` reads the tag `sha256-<digest>.sbom` when no attestation contains an SPDX or CycloneDX document. A body that is SPDX or CycloneDX JSON is written as `sbom-00-<arch>-*.json`. Any other body is written as `sbom-00-unknown.txt`.

The attachment has no in-toto signature. The script warns that the file was saved without signature verification.

Example: `registry.redhat.io/ubi9/ubi:9.8`. Its `.att` tag is SLSA provenance only. With `--platform linux/amd64`, the attachment is the amd64 SPDX document (`text/spdx+json`).

For a multi-arch image, `--platform` is passed to both downloads and selects that architecture, so the SBOM includes packages. Without `--platform`, the index SBOM lists the index and its per-architecture images. When cosign reports that the digest is not a multi-arch image, the download is retried without `--platform`.

If the image has no attestations and no SBOM attachment, the script warns and exits successfully.

## Output

| Path | Contents |
| --- | --- |
| `out/<image-slug>/sbom-NN-<arch>-spdx.json` | SPDX SBOM |
| `out/<image-slug>/sbom-NN-<arch>-cdx-<version>.json` | CycloneDX SBOM |
| `out/<image-slug>/att/attestations.jsonl` | Downloaded attestation envelopes |
| `out/<image-slug>/att/` | Per-envelope payload and predicate files |

`<image-slug>` is the image reference with `/`, `:`, and `@` replaced by `_`. `<arch>` is the majority package architecture recorded in the SBOM. An attachment uses `00` for `NN`.
