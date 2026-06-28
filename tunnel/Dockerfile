# Tiny sshuttle sidecar — routes a remote lab subnet to the collector so the
# in-container watcher can reach devices behind an SSH jump host.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass iptables procps \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir sshuttle
