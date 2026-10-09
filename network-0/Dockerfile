FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-scapy iproute2 iputils-ping tcpdump curl iptables coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && chmod u-s /usr/bin/ping \
    && mkdir -p /srv /work /opt/lab
COPY entrypoint.sh capture.sh inspect_capture.py probe_exchange.py /opt/lab/
COPY index.html /srv/index.html
RUN chmod 0555 /opt/lab/entrypoint.sh /opt/lab/capture.sh
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
