# redhat-sboms

Download and verify Sigstore attestations, then extract SBOMs for Red Hat container images.

## Prerequisites

- [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
- [`oras`](https://oras.land/docs/installation/)
- [`jq`](https://jqlang.github.io/jq/)

Images on `registry.redhat.io` need a Red Hat registry login.

## Setup

Download Red Hat release key 3 next to the script:

```bash
wget -O redhat-sigstore.pub https://security.access.redhat.com/data/63405576.txt
```

## Usage

```bash
./download-attestations.sh --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
```

For multi-arch images, pass `--platform` so the SBOM includes packages. Without it, a multi-arch tag yields the index SBOM (images only).

See `./download-attestations.sh --help` for `--output-dir` and `--key`.

## Verification

After the tag is resolved to a digest, the script:

1. Lists referrers with `oras discover`
2. Verifies the image signature with `cosign` and `redhat-sigstore.pub`
3. Downloads attestations and verifies SPDX/CycloneDX envelopes with the same key

SLSA provenance envelopes are kept but not verified. Those are signed by Konflux Tekton Chains with a different key.

## Output

| Path | Contents |
| --- | --- |
| `out/<image>/sbom-*.json` | Extracted SBOMs |
| `out/<image>/att/` | Envelopes, payloads, and predicates |
