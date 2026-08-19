#!/usr/bin/env bash

set -euo pipefail

rm -rf out/

./download-attestations.sh registry.redhat.io/openshift-gitops-1/gitops-operator-bundle:v1.21.3-1

./download-attestations.sh --platform linux/amd64 registry.redhat.io/ubi9/ubi:9.8
./download-attestations.sh --platform linux/amd64 registry.redhat.io/ubi9/openjdk-21-runtime:1.24
./download-attestations.sh --platform linux/amd64 registry.redhat.io/openshift-gitops-1/gitops-rhel9-operator:1.21

