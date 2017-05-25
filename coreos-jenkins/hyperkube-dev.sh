#!/bin/bash
set -e

COMMIT=$(git rev-parse --verify HEAD)
git tag v9.9.9+coreos.dev.$COMMIT


if [ "$BUILD_TYPE" = "binary-only" ] ; then
  # make all WHAT=cmd/hyperkube in a container
  RKT_OPTS=$(echo \
    "--volume=k8s,kind=host,source=${PWD} " \
    "--mount volume=k8s,target=/go/src/k8s.io/kubernetes")

  MAKE_BIN=$(echo \
    "cd /go/src/k8s.io/kubernetes &&" \
    "apt-get update &&" \
    "apt-get install -y rsync &&" \
    "KUBE_BUILD_PLATFORMS=linux/amd64 make all WHAT=cmd/hyperkube")
  sudo rkt run --insecure-options=image ${RKT_OPTS} docker://golang:${GO_VERSION} --exec /bin/bash -- -c "${MAKE_BIN}"

  
  # Copy binary into location expected by hyperkube makefile
  sudo chown -R jenkins:jenkins ./
  mkdir -p _output/dockerized/bin/linux/amd64
  cp _output/local/bin/linux/amd64/hyperkube _output/dockerized/bin/linux/amd64/hyperkube
  
elif [ "$BUILD_TYPE" = "quick-release" ] ; then
  # make quick-release
  KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true build/release.sh
    
elif [ "$BUILD_TYPE" = "release" ] ; then
  # NOTE(pb): until make release works, containerize make test and run that then run quick-release
  RKT_OPTS=$(echo \
    "--volume=k8s,kind=host,source=${PWD} " \
    "--mount volume=k8s,target=/go/src/k8s.io/kubernetes" \
    "--volume selinux,kind=host,source=/sys/fs/selinux,readOnly=true" \
    "--mount volume=selinux,target=/sys/fs/selinux" \
    "--stage1-from-dir=stage1-fly.aci" )

  MAKE_TESTS=$(echo \
    "cd /go/src/k8s.io/kubernetes &&" \
    "apt update &&" \
    "apt install -y rsync &&" \
    "make test")
  sudo rkt run --insecure-options=image ${RKT_OPTS} docker://golang:${GO_VERSION} --exec /bin/bash -- -c "${MAKE_TESTS}"

  sudo chown -R jenkins:jenkins ./

  # make quick-release
  KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true build/release.sh
  
else
	echo "invalid build type"
    exit 1
fi

# build hyperkube container
RKT_OPTS=$(echo \
  "--volume=k8s,kind=host,source=${PWD} " \
  "--mount volume=k8s,target=/go/src/k8s.io/kubernetes" \
  "--volume docker-client,kind=host,source=/usr/bin/docker" \
  "--mount volume=docker-client,target=/usr/bin/docker" \
  "--volume=run,kind=host,source=/run" \
  "--mount volume=run,target=/run" )
MAKE_KUBE=$(echo \
  "cd /go/src/k8s.io/kubernetes/cluster/images/hyperkube &&" \
  "make build REGISTRY=quay.io/coreos VERSION=$IMAGE_TAG")
sudo rkt run --insecure-options=image ${RKT_OPTS} docker://golang:${GO_VERSION} --exec /bin/bash -- -c "${MAKE_KUBE}"

docker tag quay.io/coreos/hyperkube-amd64:$IMAGE_TAG quay.io/coreos/hyperkube-dev:$IMAGE_TAG
docker images

if [ "$PUSH_IMAGE" = true ] ; then
	set +x # don't log passwords
    docker login --username "$DOCKER_USER" --password "$DOCKER_PASS" quay.io
    docker push quay.io/coreos/hyperkube-dev:$IMAGE_TAG
    wget https://quay.io/c1/aci/quay.io/coreos/hyperkube-dev/$IMAGE_TAG/aci/linux/amd64/ # get aci in s3 cache
fi

# Cleanup
sudo chown -R jenkins:jenkins ./
build/make-clean.sh

# all these cleanup commands SHOULD be safe to use if there are other running builds
sudo rkt gc --grace-period=0s                                          # won't delete running pods
sudo rkt image gc --grace-period=0s                                    # won't delete image in use by running pods
docker rm $(docker ps -a -q) || true                                   # delete stopped containeres
docker rmi $(docker images -q) || true                                 # delete images (fails on images currently used)
docker volume ls -qf dangling=true | xargs -r docker volume rm || true # delete orphaned volumes 

