# Copyright 2016 The Kubernetes Authors All rights reserved.
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

# build the tpm-manager image.

# TODO: figure out the best base image
# TODO: figure out how to best source the nsenter binary, if necessary
# TODO: figure out how to make a single source of version info for these
#       images
BIN_DIR=bin/linux/amd64
LOCAL_OUTPUT_DIR=../../../_output/local

build: clean
	cp ${LOCAL_OUTPUT_DIR}/${BIN_DIR}/tpm-manager .
	docker build -t ${REGISTRY}/tpm-manager:${VERSION} .

push: build
	gcloud docker push ${REGISTRY}/tpm-manager-${ARCH}:${VERSION}
ifeq ($(ARCH),amd64)
        docker tag -f ${REGISTRY}/tpm-manager-${ARCH}:${VERSION} ${REGISTRY}/tpm-manager:${VERSION}
        gcloud docker push ${REGISTRY}/tpm-manager:${VERSION}
endif

clean:
	rm -f tpm-manager

.PHONY: release
