KUBERNETES_VERSION = $(shell ./kubernetes-version.sh)

# Convert + to - for docker tag compatibility
IMAGE_VERSION = $(subst +,_,$(KUBERNETES_VERSION))

TAG = quay.io/coreos/hyperkube:$(IMAGE_VERSION)
HYPERKUBE = ../_output/dockerized/bin/linux/amd64/hyperkube
BUILD_TARGET = release

.PHONY: all container push clean

all: container

container: Dockerfile $(HYPERKUBE)
	$(eval TEMPDIR := $(shell mktemp -d -t $(KUBERNETES_VERSION).XXXX))
	cp $^ $(TEMPDIR)
	docker build -t $(TAG) $(TEMPDIR)
	rm -rf $(TEMPDIR)

push:
	docker push $(TAG)

$(HYPERKUBE):
	make -C .. $(BUILD_TARGET)

clean:
	make -C .. clean

