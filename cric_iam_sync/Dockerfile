FROM gitlab-registry.cern.ch/linuxsupport/alma9-base

RUN cd /etc/yum.repos.d; curl -O https://repo.data.kit.edu//data-kit-edu-almalinux9.repo

RUN yum install epel-release -y

RUN yum upgrade -y \
    && yum clean all \
    && rm -rf /var/cache/yum

RUN yum -y install epel-release oidc-agent-cli oidc-agent-desktop oidc-agent-libs oidc-agent-devel openssl python3-pip CERN-CA-certs s-nail

COPY . /src
WORKDIR /src

RUN pip3 install --no-cache-dir -r requirements.txt


RUN chgrp -R 0 /src && \
    chmod -R g+rwX /src
RUN chmod +x ./cronjob.sh
