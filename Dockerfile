FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS rclone
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
# Rebuild with the upstream gRPC fix plus patched Go and x/net dependencies.
RUN go mod download github.com/rclone/rclone@v1.75.1 \
    && cp -a /go/pkg/mod/github.com/rclone/rclone@v1.75.1/. /src/ \
    && chmod -R u+w /src \
    && go get google.golang.org/grpc@v1.85.0-dev.0.20260825072537-93e31b48545e \
       golang.org/x/net@v0.60.0 \
    && go build -mod=readonly -trimpath \
       -ldflags="-s -w -X github.com/rclone/rclone/fs.Version=v1.75.1-homelab.2" \
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
