FROM debian:12-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      netcat-openbsd \
      python3 \
      python3-pycryptodome \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --home-dir /home/oracle --shell /usr/sbin/nologin oracle \
 && install -d -o oracle -g oracle -m 0700 /state

COPY oracle.py /usr/local/bin/ra2r-oracle
RUN chmod 0755 /usr/local/bin/ra2r-oracle

USER oracle
EXPOSE 5900
ENTRYPOINT ["/usr/local/bin/ra2r-oracle"]
