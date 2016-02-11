KUBERNETES_VERSION = $(shell ./kubernetes-version.sh)

# Convert + to - for docker tag compatibility
IMAGE_VERSION = $(subst +,-,$(KUBERNETES_VERSION))

TAG = quay.io/coreos/hyperkube:$(IMAGE_VERSION)
HYPERKUBE = ../_output/dockerized/bin/linux/amd64/hyperkube

.PHONY: all container push clean

all: container

container: Dockerfile $(HYPERKUBE)
	$(eval TEMPDIR := $(shell mktemp -d -t $(KUBERNETES_VERSION)))
	cp $^ $(TEMPDIR)
	docker build -t $(TAG) $(TEMPDIR)
	@$(foreach p,$^,rm $(TEMPDIR)/p;)
	rmdir $(TEMPDIR)

push:
	docker push $(TAG)

$(HYPERKUBE):
	make -C .. release

clean:
	make -C .. clean

