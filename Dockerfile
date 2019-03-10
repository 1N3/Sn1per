FROM kalilinux/kali-linux-docker

LABEL org.label-schema.name='Sn1per - Kali Linux' \
    org.label-schema.description='Automated pentest framework for offensive security experts' \
    org.label-schema.usage='https://github.com/1N3/Sn1per' \
    org.label-schema.url='https://github.com/1N3/Sn1per' \
    org.label-schema.vendor='https://xerosecurity.com' \
    org.label-schema.schema-version='1.0' \
    org.label-schema.docker.cmd.devel='docker run --rm -ti hariomv/sniper' \
    MAINTAINER="Hariom Vashisth <hariom.devops@gmail.com>"

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
    && apt-get -yqq update \
    && apt-get -yqq dist-upgrade \
    && apt-get clean

RUN \
    apt-get --yes install git \
    && mkdir -p security \
    && cd security \
    && git clone https://github.com/1N3/Sn1per.git \
    && cd Sn1per \
    && ./install.sh

CMD ["bash"]

