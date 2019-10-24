FROM kalilinux/kali-linux-docker

LABEL org.label-schema.name='Sn1per - Kali Linux' \
    org.label-schema.description='Automated pentest framework for offensive security experts' \
    org.label-schema.usage='https://github.com/1N3/Sn1per' \
    org.label-schema.url='https://github.com/1N3/Sn1per' \
    org.label-schema.vendor='https://xerosecurity.com' \
    org.label-schema.schema-version='1.0' \
    org.label-schema.docker.cmd.devel='docker run --rm -ti hariomv/sniper' \
    MAINTAINER="@xer0dayz"

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
    && apt-get -yqq update \
    && apt-get -yqq upgrade \
    && apt-get -yqq dist-upgrade \
    && apt-get clean

RUN apt-get install -y metasploit-framework

RUN sed -i 's/systemctl status ${PG_SERVICE}/service ${PG_SERVICE} status/g' /usr/bin/msfdb && \
    service postgresql start && \
    msfdb reinit
# Establish a working directory
RUN apt-get install -y git \
    && cd /root \
    && git clone --recursive git://github.com/anoncam/Sn1per.git \
    && cd /root/Sn1per \
    && bash /root/Sn1per/install.sh
# Add the following to run the professional version.
# cd /usr/share/sniper/
# wget https://xerosecurity.com/pro/6.0/[YOURCUSTOMLICENSEKEYHERE]/pro.sh -O pro.sh
# If you did that: you need to configure the entrypoint and config/expose the web service.
CMD ["/bin/bash"]