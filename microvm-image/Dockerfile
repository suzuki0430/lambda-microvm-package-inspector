FROM node:24-bookworm-slim@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf

RUN apt-get update \
    && apt-get install --no-install-recommends -y python3 strace ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/sandbox --uid 10001 sandbox \
    && mkdir -p /opt/package-inspector /work/scans \
    && chown root:root /opt/package-inspector /work/scans \
    && chmod 0755 /opt/package-inspector /work/scans

COPY runner-src/ /opt/package-inspector/src/
COPY fixtures/ /opt/package-inspector/fixtures/

ENV PYTHONPATH=/opt/package-inspector/src \
    PYTHONUNBUFFERED=1 \
    INSPECTOR_MICROVM_IMAGE_VERSION=cdk-managed

EXPOSE 8080

# The trusted observer starts as root so strace can follow a child after it
# drops to UID 10001. Only npm lifecycle code runs as the sandbox user.
CMD ["python3", "-m", "package_inspector.cli", "serve", "--catalog", "/opt/package-inspector/fixtures/catalog.json", "--workspace", "/work/scans", "--port", "8080"]
