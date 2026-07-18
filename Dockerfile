# syntax=docker/dockerfile:1

# nftui container image — a small runtime layer that bundles the nft(8) CLI
# nftui shells out to at runtime (see nft/nft_linux.go).
#
# Build:
#   docker build -t nftui:local .
#   docker build -t nftui:1.2.0 --build-arg VERSION=1.2.0 .
#
# Run (manages the HOST ruleset — needs the host network namespace, the
# NET_ADMIN capability, and an interactive TTY for the TUI):
#   docker run --rm -it --network host --cap-add NET_ADMIN nftui:local
#
# See docker-compose.yml for the Compose equivalent.

# ---- build stage ----------------------------------------------------------
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

# Version string baked into `nftui --version`; override with
# --build-arg VERSION=<tag>. Defaults to "dev" for local builds.
ARG VERSION=dev

WORKDIR /src

# Resolve the module graph first so the layer is cached across source-only edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Match the Goreleaser / Nix binary shape: static (CGO-free), trimmed paths,
# stripped symbol table, version injected via -ldflags.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nftui .

# ---- runtime stage --------------------------------------------------------
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# nftui shells out to the nft(8) binary, so the runtime image must ship the
# nftables userspace tools.
RUN apk add --no-cache nftables

COPY --from=build /out/nftui /usr/bin/nftui
COPY man/nftui.1 /usr/share/man/man1/nftui.1

# nftui needs CAP_NET_ADMIN. The container runs as root by default; the
# capability is granted at `docker run` time (--cap-add NET_ADMIN) and the
# container boundary is the isolation layer. Combined with --network host this
# manages the host's ruleset. For a non-root setup, grant the file capability
# (setcap cap_net_admin=ep /usr/bin/nftui) and add a USER — see README "Docker".
ENTRYPOINT ["/usr/bin/nftui"]
