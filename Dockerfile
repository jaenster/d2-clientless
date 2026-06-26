# Static musl binaries via Zig, shipped on scratch. Multi-arch (amd64/arm64) with buildx.
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM alpine:3.20 AS build
ARG BUILDARCH
ARG TARGETARCH
ARG ZIG_VERSION=0.16.0
RUN apk add --no-cache curl xz tar
# Zig for the build host's arch.
RUN set -eux; \
    case "$BUILDARCH" in amd64) ZA=x86_64;; arm64) ZA=aarch64;; *) echo "unsupported build arch $BUILDARCH"; exit 1;; esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZA}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -s /opt/zig/zig /usr/local/bin/zig; zig version
WORKDIR /src
COPY build.zig ./
COPY src ./src
# Cross-compile to the target arch, statically linked against musl.
RUN set -eux; \
    case "$TARGETARCH" in amd64) ZT=x86_64-linux-musl;; arm64) ZT=aarch64-linux-musl;; *) echo "unsupported target arch $TARGETARCH"; exit 1;; esac; \
    zig build -Dtarget="$ZT" -Doptimize=ReleaseSafe

FROM scratch
COPY --from=build /src/zig-out/bin/clientless /clientless
# One binary: BNCS/MCP/game by default; `clientless bnftp ...` for the BNFTP file client.
ENTRYPOINT ["/clientless"]
