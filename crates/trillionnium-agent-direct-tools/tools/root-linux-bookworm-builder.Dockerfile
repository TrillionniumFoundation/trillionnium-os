# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM debian@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e

ARG DEBIAN_FRONTEND=noninteractive

# Exact package versions make the locally built runtime rootfs reviewable.
# The resulting image must still be invoked by its content digest. Registry,
# package-mirror and image-build provenance require independent approval before
# this can be treated as a production builder.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      binutils=2.40-2 \
      file=1:5.44-3 \
      gcc=4:12.2.0-3 \
      gcc-12=12.2.0-14+deb12u1 \
      libc6-dev=2.36-9+deb12u14 \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=C \
    LC_ALL=C \
    TZ=UTC

LABEL org.trillionnium.root-linux.builder-contract="bookworm-content-addressed-candidate-v1" \
      org.trillionnium.root-linux.base-manifest="sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e" \
      org.trillionnium.root-linux.production-approved="false"
