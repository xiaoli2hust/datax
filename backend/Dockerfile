FROM python:3.12.13-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10001 dataxstudio \
    && useradd --system --uid 10001 --gid dataxstudio --home /app dataxstudio

WORKDIR /app
COPY pyproject.toml alembic.ini requirements.lock build-requirements.lock ./
COPY migrations ./migrations
COPY src ./src
RUN python -m pip install --require-hashes -r build-requirements.lock \
    && python -m pip install --require-hashes -r requirements.lock \
    && python -m pip install --no-build-isolation --no-deps . \
    && python -m pip uninstall --yes pip setuptools wheel \
    && find /usr/local/lib/python3.12/ensurepip -depth -delete \
    && python -c 'import importlib.util; missing = ("pip", "setuptools", "wheel"); assert all(importlib.util.find_spec(name) is None for name in missing)' \
    && test ! -e /usr/local/bin/pip \
    && test ! -e /usr/local/bin/pip3 \
    && test ! -e /usr/local/bin/wheel

RUN mkdir -p /var/lib/datax-studio/logs \
    && chown -R dataxstudio:dataxstudio /app /var/lib/datax-studio

USER dataxstudio
EXPOSE 8000

CMD ["uvicorn", "datax_studio.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
