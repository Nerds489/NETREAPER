# syntax=docker/dockerfile:1
# NETREAPER container image (#94, optional). Two stages:
#
#   cli   NETREAPER installed, no security tools. Small, fast, and all most CI
#         and planning/dry-run use needs. `netreaper --version`, `netreaper
#         <cmd> --help`, `bin/netreaper-install --dry-run all`.
#   full  cli + the security-tool arsenal via the bundled installer. Heavy
#         (hundreds of MB, many packages); build on demand with
#         `--target full`, not by default.
#
# The image invokes the INSTALLED `netreaper` console script; it does not
# re-derive an install root the way bin/netreaper-install once did. pip install
# remains the baseline install path off-image (README Installation).
#
# Wireless capture/injection from a container needs host access that is NOT
# baked in here (it would make the image unusable as a plain CLI): pass it at
# run time, e.g.
#   docker run --rm -it --net=host \
#     --cap-add=NET_ADMIN --cap-add=NET_RAW \
#     --device=/dev/bus/usb netreaper:full wifi scan wlan0mon
# See docker/README.md.

FROM python:3.12-slim AS cli

# git: some installer methods and the operator's own clone workflow expect it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/netreaper
COPY . .
RUN pip install --no-cache-dir .

# A planning/dry-run container is unprivileged; the scope gate stays deny-by-
# default and privileged scans are refused unless run with the caps above.
ENTRYPOINT ["netreaper"]
CMD ["--help"]


FROM cli AS full

# The security-tool arsenal. Uses the bundled installer, which resolves the
# distribution's package manager. Heavy and slow; excluded from the default
# build. `essentials` keeps it to the short list; swap for `all` if you want the
# lot. Kept non-fatal so a single unavailable tool does not fail the image.
RUN sudo=/usr/bin/sudo; command -v sudo >/dev/null || sudo=""; \
    ./bin/netreaper-install essentials || true
