# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build the hyperkube image.
#
# Usage:
#   [ARCH=amd64] [REGISTRY="gcr.io/google_containers"] make (build|push) VERSION={some_released_version_of_kubernetes}

REGISTRY?=gcr.io/google_containers
ARCH?=amd64
OUT_DIR?=_output
TEMP_DIR:=$(shell mktemp -d -t hyperkubeXXXXXX)
CNI_RELEASE=v0.6.0
CACHEBUST?=1
QEMUVERSION=v2.7.0

UNAME_S:=$(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	SED_CMD?=sed -i ""
endif
ifeq ($(UNAME_S),Linux)
	SED_CMD?=sed -i
endif

ifeq ($(ARCH),amd64)
	BASEIMAGE?=debian:jessie
endif
ifeq ($(ARCH),arm)
	BASEIMAGE?=armhf/debian:jessie
	QEMUARCH=arm
endif
ifeq ($(ARCH),arm64)
	BASEIMAGE?=aarch64/debian:jessie
	QEMUARCH=aarch64
endif
ifeq ($(ARCH),ppc64le)
	BASEIMAGE?=ppc64le/debian:jessie
	QEMUARCH=ppc64le
endif
ifeq ($(ARCH),s390x)
	BASEIMAGE?=s390x/debian:jessie
	QEMUARCH=s390x
endif

all: build

build:

ifndef VERSION
    $(error VERSION is undefined)
endif
	cp -r ./* ${TEMP_DIR}
	mkdir -p ${TEMP_DIR}/cni-bin/bin

	cp ../../../$(OUT_DIR)/dockerized/bin/linux/${ARCH}/hyperkube ${TEMP_DIR}
	chmod a+rx ${TEMP_DIR}/hyperkube

	cd ${TEMP_DIR} && sed -i.back "s|ARCH|${QEMUARCH}|g" Dockerfile
	cd ${TEMP_DIR} && sed -i.back "s|BASEIMAGE|${BASEIMAGE}|g" Dockerfile
ifeq ($(CACHEBUST),1)
	cd ${TEMP_DIR} && sed -i.back "s|CACHEBUST|$(shell uuidgen)|g" Dockerfile
endif

ifeq ($(ARCH),amd64)
	# When building "normally" for amd64, remove the whole line, it has no part in the amd64 image
	cd ${TEMP_DIR} && ${SED_CMD} "/CROSS_BUILD_/d" Dockerfile
else
	cd ${TEMP_DIR} && ${SED_CMD} "s/CROSS_BUILD_//g" Dockerfile

	# When cross-building, only the placeholder "CROSS_BUILD_" should be removed
	# Register /usr/bin/qemu-ARCH-static as the handler for ARM binaries in the kernel
	docker run --rm --privileged multiarch/qemu-user-static:register --reset
	curl -sSL --retry 5 https://github.com/multiarch/qemu-user-static/releases/download/$(QEMUVERSION)/x86_64_qemu-${QEMUARCH}-static.tar.gz | tar -xz -C ${TEMP_DIR}
endif
	# Download CNI
	curl -sSL --retry 5 https://github.com/containernetworking/cni/releases/download/${CNI_RELEASE}/cni-${ARCH}-${CNI_RELEASE}.tgz | tar -xz -C ${TEMP_DIR}/cni-bin/bin
	curl -sSL --retry 5 https://github.com/containernetworking/plugins/releases/download/${CNI_RELEASE}/cni-plugins-${ARCH}-${CNI_RELEASE}.tgz | tar -xz -C ${TEMP_DIR}/cni-bin/bin
	curl -sSL --retry 5 -o  ${TEMP_DIR}/cni-bin/bin/calico https://github.com/projectcalico/calico-cni/releases/download/v1.11.0/calico
	chmod +x ${TEMP_DIR}/cni-bin/bin/calico

	docker build --pull -t ${REGISTRY}/hyperkube-${ARCH}:${VERSION} ${TEMP_DIR}
	rm -rf "${TEMP_DIR}"

push: build
	gcloud docker -- push ${REGISTRY}/hyperkube-${ARCH}:${VERSION}
ifeq ($(ARCH),amd64)
	docker rmi ${REGISTRY}/hyperkube:${VERSION} 2>/dev/null || true
	docker tag ${REGISTRY}/hyperkube-${ARCH}:${VERSION} ${REGISTRY}/hyperkube:${VERSION}
	gcloud docker -- push ${REGISTRY}/hyperkube:${VERSION}
endif

.PHONY: all
