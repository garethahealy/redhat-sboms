# redhat-sboms

Download and verify Sigstore attestations, then extract SBOMs for Red Hat container images.

Requires `cosign`, `oras`, and `jq`. Images on `registry.redhat.io` need a Red Hat registry login.

Download Red Hat release key 3 as `redhat-sigstore.pub` next to the script:

```bash
wget -O redhat-sigstore.pub https://security.access.redhat.com/data/63405576.txt
```

Downloaded `attestations.jsonl` is verified with `cosign` and that key. After the digest is resolved, `oras discover` lists referrers and `cosign verify` checks the image signature. SLSA provenance envelopes are kept but not verified; those are signed by Konflux Tekton Chains with a different key. For multi-arch images, pass `--platform` so the SBOM includes packages rather than only the image index.

```bash
./download-attestations.sh --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
```

SBOMs land in `out/<image>/`. Attestation envelopes, payloads, and predicates go in `out/<image>/att/`.
