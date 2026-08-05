FROM python:3.11-slim-bookworm

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT
LABEL org.opencontainers.image.title="research-workbench-gate0-isolated-parser"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m pip install --no-cache-dir \
    "jsonschema==4.25.1" \
    "pypdf==6.14.2" \
    "reportlab==4.5.1"

COPY contracts /app/contracts
COPY fixtures /app/fixtures
COPY gate0 /app/gate0
COPY linux /app/linux
COPY scripts /app/scripts
COPY tests /app/tests

USER 65532:65532

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
