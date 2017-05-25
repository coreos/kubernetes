# NOTE(pb): until make release works, containerize make test 
# and run that then run quick-release
RKT_OPTS=$(echo \
  "--volume=k8s,kind=host,source=${PWD} " \
  "--mount volume=k8s,target=/go/src/k8s.io/kubernetes" \
  "--volume selinux,kind=host,source=/sys/fs/selinux,readOnly=true" \
  "--mount volume=selinux,target=/sys/fs/selinux" \
  "--stage1-from-dir=stage1-fly.aci" )

MAKE_TESTS=$(echo \
  "cd /go/src/k8s.io/kubernetes &&" \
  "apt-get update &&" \
  "apt-get install -y rsync &&" \
  "make test")
sudo rkt run --insecure-options=image ${RKT_OPTS} docker://golang:${GO_VERSION} --exec /bin/bash -- -c "${MAKE_TESTS}"
sudo chown -R jenkins:jenkins ./

# make quick-release
KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true build/release.sh

# MAKE TAG DOCKER-SAFE
IMAGE_TAG=$(echo $RELEASE_TAG | tr + _)

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

docker tag quay.io/coreos/hyperkube-amd64:$IMAGE_TAG quay.io/coreos/hyperkube:$IMAGE_TAG
docker images

if [ "$PUSH_IMAGE" = true ] ; then
	set +x # don't log passwords
    docker login quay.io --username $DOCKER_USER --password $DOCKER_PASS
    docker push quay.io/coreos/hyperkube:$IMAGE_TAG
    wget https://quay.io/c1/aci/quay.io/coreos/hyperkube/$IMAGE_TAG/aci/linux/amd64/ # warm cache before it gets hit in parallel
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

