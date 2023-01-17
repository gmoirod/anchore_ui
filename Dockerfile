FROM ubuntu:18.04
LABEL   author.original="zj1244" \
        author.contributor="gmoirod"

ENV LC_ALL C.UTF-8

RUN set -x \
    && apt-get update \
    && apt-get upgrade \
    && apt-get install -y --no-install-recommends \
        python-dev=2.7.15~rc1-1 \
        python-setuptools=39.0.1-2 \
        python-pip=9.0.1-2.3~ubuntu1.18.04.5 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/anchore_ui
COPY . /opt/anchore_ui

RUN set -x \
    && pip --no-cache-dir install -r /opt/anchore_ui/requirements.txt \
    && cp /opt/anchore_ui/config.py.sample /opt/anchore_ui/config.py

WORKDIR /opt/anchore_ui
ENTRYPOINT ["python","run.py"]
CMD ["/usr/bin/tail", "-f", "/dev/null"]
USER 1001
