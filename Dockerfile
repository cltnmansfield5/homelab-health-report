FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS rclone
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
# Rebuild the release with the upstream fix for CVE-2026-84445.
RUN go mod download github.com/rclone/rclone@v1.75.1 \
    && cp -a /go/pkg/mod/github.com/rclone/rclone@v1.75.1/. /src/ \
    && chmod -R u+w /src \
    && go get google.golang.org/grpc@v1.85.0-dev.0.20260825072537-93e31b48545e \
    && go build -mod=readonly -trimpath \
       -ldflags="-s -w -X github.com/rclone/rclone/fs.Version=v1.75.1-homelab.1" \
       -o /out/rclone .

FROM python:3.13-alpine3.24@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a AS core
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
RUN apk upgrade --no-cache \
    && apk add --no-cache tzdata ca-certificates \
    && python -m pip uninstall --yes pip setuptools wheel \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && printf '\ntext/markdown md markdown\n' >> /etc/mime.types
COPY homelab_health/ /app/homelab_health/
# Only non-secret, repository-owned settings belong in the image.
COPY config/collector.toml config/upload.toml /config/
USER 10001:10001
ENTRYPOINT ["python", "-m", "homelab_health"]

FROM core AS uploader
COPY --from=rclone /out/rclone /usr/bin/rclone
COPY --from=rclone /src/COPYING /usr/share/licenses/rclone/COPYING

FROM core AS collector
