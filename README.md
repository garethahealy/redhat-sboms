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

The first command selects the amd64 manifest of a multi-arch image. Its SBOM is the SPDX attestation on that manifest. The second image is single-arch and also publishes its SBOM as an SPDX attestation.

`./download-attestations.sh --help` lists `--output-dir`, `--platform`, `--key`, `--skip-verify-image`, and `--skip-verify-attestation`.

`download-from-mapping.sh` runs that script for each selected source in an oc-mirror v2 `mapping.txt`. Both methods below apply to every image. `--platform`, `--key`, `--skip-verify-image`, and `--skip-verify-attestation` are forwarded.

```bash
./download-from-mapping.sh --platform linux/amd64 oc-mirror-data/working-dir/dry-run/mapping.txt
```

`./download-from-mapping.sh --help` lists `--source` and `--print`.

## Methods

The tag is resolved to a digest with `oras`. When `--platform` is set, oras selects that platform's manifest. Referrers are listed with `oras discover`. An empty referrer list is normal on `registry.redhat.io`, which publishes these objects as Cosign tags. The image signature is then verified with `cosign` and `redhat-sigstore.pub`, unless `--skip-verify-image` is set. Transparency-log checks are skipped.

Every SPDX or CycloneDX document in the attestations is written. The attachment is downloaded only when that count is zero.

### Attestation

`cosign download attestation` reads the tag `sha256-<digest>.att`.

- A Konflux SPDX statement uses predicate type `https://spdx.dev/Document`. The predicate is the SBOM.
- An older OSBS attestation carries CycloneDX in `predicate.Data`.
- SPDX and CycloneDX envelopes are verified with `redhat-sigstore.pub`, unless `--skip-verify-attestation` is set. The script warns if at least one of those envelopes was checked and none verified.
- SLSA provenance (`https://slsa.dev/provenance/`) is stored under `att/` and skipped. Konflux Tekton Chains signs it with a different key.

Example: `registry.redhat.io/ubi9/ubi:9.8` with `--platform linux/amd64`. The amd64 manifest's attestations include an SPDX document, which is the SBOM, and SLSA provenance. `registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1` is single-arch and publishes its SBOM as an SPDX attestation.

### SBOM attachment

`cosign download sbom` reads the tag `sha256-<digest>.sbom` when no attestation contains an SPDX or CycloneDX document. A body that is SPDX or CycloneDX JSON is written as `sbom-00-<arch>-*.json`. Any other body is written as `sbom-00-unknown.txt`.

The attachment has no in-toto signature. The script warns that the file was saved without signature verification.

For a multi-arch image, `--platform` selects that architecture's manifest when the tag is resolved, so the SBOM is the one for that architecture. Downloads then use that digest. Because the digest is no longer an index, cosign is retried without `--platform`. Without `--platform`, resolution stays on the tag digest. When a single-arch image does not match `--platform`, resolution is retried without it.

If the image has no attestations and no SBOM attachment, the script warns and exits successfully.

## Output

| Path | Contents |
| --- | --- |
| `out/<image-slug>/sbom-NN-<arch>-spdx.json` | SPDX SBOM |
| `out/<image-slug>/sbom-NN-<arch>-cdx-<version>.json` | CycloneDX SBOM |
| `out/<image-slug>/att/attestations.jsonl` | Downloaded attestation envelopes |
| `out/<image-slug>/att/` | Per-envelope payload and predicate files |

`<image-slug>` is the image reference with `/`, `:`, and `@` replaced by `_`. `<arch>` is the majority package architecture recorded in the SBOM. An attachment uses `00` for `NN`.
