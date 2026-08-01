FROM postgres:15.18-alpine3.24@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk add --no-cache \
        nftables \
        python3 \
    && test -x /usr/local/bin/psql \
    && rm -rf /var/cache/apk/*

COPY guard.py healthcheck.py /opt/datax-egress-guard/

RUN chmod 0555 \
        /opt/datax-egress-guard/guard.py \
        /opt/datax-egress-guard/healthcheck.py \
    && mkdir -p /run/datax-egress-guard \
    && chmod 0700 /run/datax-egress-guard

USER 0

ENTRYPOINT ["python3", "/opt/datax-egress-guard/guard.py"]
