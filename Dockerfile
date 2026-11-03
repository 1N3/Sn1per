FROM docker.io/kalilinux/kali-rolling:latest

LABEL org.label-schema.name='Sn1per - Kali Linux' \
    org.label-schema.description='Automated pentest framework for offensive security experts' \
    org.label-schema.usage='https://github.com/1N3/Sn1per' \
    org.label-schema.url='https://github.com/1N3/Sn1per' \
    org.label-schema.vendor='https://sn1persecurity.com' \
    org.label-schema.schema-version='1.0' \
    org.label-schema.docker.cmd.devel='docker run --rm -ti xer0dayz/sniper' \
    MAINTAINER="@xer0dayz"

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
ENV DEBIAN_FRONTEND=noninteractive

RUN set -x \
        && apt -yqq update \
        && apt -yqq full-upgrade \
        && apt clean
RUN apt install --yes metasploit-framework

RUN sed -i 's/systemctl status ${PG_SERVICE}/service ${PG_SERVICE} status/g' /usr/bin/msfdb && \
    service postgresql start && \
    msfdb reinit

WORKDIR /usr/src/app/Sn1per

RUN apt --yes install git bash

# Build the checked-out tree so CI validates the commit under test,
# instead of re-cloning the upstream default branch.
COPY . /usr/src/app/Sn1per

# -y skips the installer's interactive confirmation prompt, which
# otherwise hangs a non-interactive Docker build.
#
# `sniper -u force` was dropped: -u ignores the force argument and prompts
# via `read ans` whenever upstream is ahead of the built version, so it would
# hang the build as soon as a new tag lands. Answering it would also re-clone
# upstream and re-run the interactive installer. `--help` smoke-tests the
# install instead.
RUN ./install.sh -y && sniper --help >/dev/null

CMD ["sniper"]