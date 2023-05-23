### Usage:
###   docker build -t syzscope --build-arg UID=$(id -u) --build-arg GID=$(id -g) .
###   # Run docker either privileged or with --device=/dev/kvm to permit
###   # using kvm in the container.
###   docker run --rm --privileged -ti -p 2222:22 syzscope 
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
# Set TZ and install tzdata early so 'requirements.sh' will not wait forever to prompt.
ENV TZ=Etc/UTC

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y git \
    python3 python3-pip \
    python3-venv sudo \
    tzdata locales

ARG UNAME=user
ARG UID=1000
ARG GID=1000
RUN set -x && groupadd -g ${GID} -o ${UNAME} && \
    useradd -u ${UID} -g ${GID} -G sudo -ms /bin/bash ${UNAME} && \
    echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN addgroup kvm && usermod -a -G kvm ${UNAME}

RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environ && \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
    echo "LANG=en_US.UTF-8" > /etc/locale.conf && \
    locale-gen en_US.UTF-8

USER ${UNAME}

# Modify shell encoding for running 'pwndbg'
RUN echo "export LANG=en_US.UTF-8" >> /home/${UNAME}/.bashrc
RUN echo "export LC_ALL=en_US.UTF-8" >> /home/${UNAME}/.bashrc

WORKDIR /home/${UNAME}
RUN cd /home/${UNAME} && git clone https://github.com/plummm/SyzScope.git

WORKDIR /home/${UNAME}/SyzScope
# Install SyzScope python dependencies
RUN pip3 install -r requirements.txt

# Install SyzScope system dependencies
RUN cd /home/${UNAME}/SyzScope/ && bash -ex syzscope/scripts/requirements.sh

CMD ["bash"]
