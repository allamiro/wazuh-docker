# Wazuh agent + the Python Docker SDK required by the docker-listener wodle.
#
# The stock wazuh/wazuh-agent image ships python3 without pip and without the
# 'docker' library, so the wodle starts, logs "Starting to listening Docker
# events" and then silently produces nothing (ModuleNotFoundError). This image
# adds the dependency.
#
# Built by './wazuh-deploy.sh fetch' on the CONNECTED host and carried inside
# the air-gap bundle like any other image - the air-gapped target never needs
# pip or an index.
ARG WAZUH_VERSION=4.14.7
FROM wazuh/wazuh-agent:${WAZUH_VERSION}
USER root
RUN python3 -m ensurepip --default-pip \
 && python3 -m pip install --no-cache-dir --upgrade pip \
 && python3 -m pip install --no-cache-dir docker==7.1.0 \
 && python3 -c "import docker; print('docker SDK', docker.__version__)"
