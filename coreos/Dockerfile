FROM debian:jessie

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y \
    && DEBIAN_FRONTEND=noninteractive apt-get -yy -q \
    install \
    iptables \
    ethtool \
    ca-certificates \
    file \
    util-linux \
    socat \
    curl \
    git \
    nfs-common \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get autoremove -y \
    && DEBIAN_FRONTEND=noninteractive apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cp /usr/bin/nsenter /nsenter

COPY hyperkube /hyperkube
RUN chmod a+rx /hyperkube

RUN ln -s /hyperkube /kubelet
RUN mkdir -p /opt/cni/bin
RUN curl -L https://github.com/appc/cni/releases/download/v0.2.0/cni-v0.2.0.tgz | tar zxv -C /opt/cni/bin
ADD https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico /opt/cni/bin
RUN chmod +x /opt/cni/bin/*
