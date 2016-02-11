#!/bin/bash
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..
source ${KUBE_ROOT}/hack/lib/version.sh
kube::version::get_version_vars
echo "${KUBE_GIT_VERSION}"
