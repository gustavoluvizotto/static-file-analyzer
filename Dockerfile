# Container image for `triage`. Build arguments and runtime sandbox settings are
# defined in docker-compose.yml; build with `podman compose build` and run scans
# through run_isolated.sh.
#
# Build arguments (defaults below, overridden from docker-compose.yml):
#   PYTHON_IMAGE  base image; pin by digest for reproducible builds, e.g.
#                 docker.io/library/python:3.12-slim@sha256:<digest>
#   TRIAGE_UID    numeric UID/GID the scanner runs as (non-root)
#   TRIAGE_GID
ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim

# --- build stage: install triage and its pinned dependencies into a venv ----
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml requirements.lock ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --only-binary=:all: -c requirements.lock . \
 && /opt/venv/bin/pip uninstall -y pip \
 && /opt/venv/bin/python -m compileall -q /opt/venv

# --- runtime stage: only the venv and the rules, run as a fixed non-root UID --
FROM ${PYTHON_IMAGE}
ARG TRIAGE_UID=10001
ARG TRIAGE_GID=10001
# Remove setuid/setgid bits (su, passwd, mount, ...): nothing in the image can
# raise privileges, even if no-new-privileges were missing at runtime.
RUN test "$TRIAGE_UID" -gt 0 && test "$TRIAGE_GID" -gt 0 \
 && groupadd --system --gid "$TRIAGE_GID" triage \
 && useradd --system --uid "$TRIAGE_UID" --gid "$TRIAGE_GID" --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin triage \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
COPY --from=build /opt/venv /opt/venv
# Owned by root and not writable by the triage user.
COPY rules /opt/triage/rules
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Numeric UID so runtimes can verify "non-root" without reading /etc/passwd.
USER ${TRIAGE_UID}:${TRIAGE_GID}
WORKDIR /
ENTRYPOINT ["triage"]
CMD ["--help"]
