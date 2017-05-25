RELEASE_BRANCH="coreos-hyperkube-${RELEASE_TAG}"
PATCHSET_BRANCH="${RELEASE_TAG}-patchset"

git remote add coreos git@github.com:coreos/kubernetes.git

# Create a release branch from vanilla upstream release tag
RB_EXISTS=$(GIT_SSH_COMMAND="ssh -i ${DEPLOY_KEY}" git ls-remote coreos ${RELEASE_BRANCH})
if [ -n "${RB_EXISTS}" ]; then
    echo "Release branch ${RELEASE_BRANCH} already exists. Skipping"
else
	echo "Creating release branch: ${RELEASE_BRANCH}"
    git checkout ${RELEASE_TAG} -b ${RELEASE_BRANCH}
    if [ "${DRYRUN}" = false ]; then
        GIT_SSH_COMMAND="ssh -i ${DEPLOY_KEY}" git push coreos ${RELEASE_BRANCH}
    fi
fi
   

# Create a branch containing previous release patchset
if [ -n "${PATCHES_FROM}" ]; then
	GIT_SSH_COMMAND="ssh -i ${DEPLOY_KEY}" git fetch coreos
    git -c "user.name=Jenkins Deploy" -c "user.email=jenkins@coreos.com" rebase coreos/${RELEASE_BRANCH} coreos/${PATCHES_FROM}
    git checkout -b ${PATCHSET_BRANCH}
    if [ "${DRYRUN}" = false ]; then
        GIT_SSH_COMMAND="ssh -i ${DEPLOY_KEY}" git push coreos ${PATCHSET_BRANCH}
    fi
fi

echo
echo "Release branch: https://github.com/coreos/kubernetes/tree/${RELEASE_BRANCH}"
if [ -z "${PATCHES_FROM}" ]; then
    exit 0 # Done.
fi

echo "Patchset branch: https://github.com/coreos/kubernetes/tree/${PATCHSET_BRANCH}"
echo 
echo "Open a pull-request for patchset"
echo "https://github.com/coreos/kubernetes/compare/${RELEASE_BRANCH}...coreos:${PATCHSET_BRANCH}?expand=1"
