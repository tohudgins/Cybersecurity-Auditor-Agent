FROM python:3.12-slim AS runtime

ARG GITLEAKS_VERSION=8.21.2
ARG HADOLINT_VERSION=2.12.0

# Install Trivy (CVE + IaC misconfig scanner) + gitleaks (secrets) + hadolint
# (Dockerfile linter) in one layer. Semgrep (multi-language SAST) is installed via
# pip below as part of the `scanners` extra.
# Trivy comes from Aqua Security's official Debian repo.
# gitleaks and hadolint ship as release binaries, downloaded for the host architecture.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget gnupg ca-certificates \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    # gitleaks: pick arch-matching release tarball (amd64 → x64; arm64 → arm64)
    && DPKG_ARCH="$(dpkg --print-architecture)" \
    && case "$DPKG_ARCH" in \
         amd64) GL_ARCH=x64 ;; \
         arm64) GL_ARCH=arm64 ;; \
         *)     GL_ARCH=x64 ;; \
       esac \
    && wget -qO /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    # hadolint: release binary named by arch (x86_64 / arm64)
    && case "$DPKG_ARCH" in \
         amd64) HL_ARCH=x86_64 ;; \
         arm64) HL_ARCH=arm64 ;; \
         *)     HL_ARCH=x86_64 ;; \
       esac \
    && wget -qO /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HL_ARCH}" \
    && chmod +x /usr/local/bin/hadolint \
    && apt-get purge -y wget gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[scanners]"

COPY app.py ./
COPY data/ ./data/
COPY docker/entrypoint.sh ./docker/entrypoint.sh
RUN chmod +x ./docker/entrypoint.sh

EXPOSE 8501

ENTRYPOINT ["./docker/entrypoint.sh"]
