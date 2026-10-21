# A static binary built on Alpine, run from an empty image as an unprivileged user.
# docs/running.md shows how to run it; the release workflow builds it for amd64 and arm64.

FROM rust:1.99.1-alpine3.24 AS build
RUN apk add --no-cache build-base cmake perl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY assets assets
COPY src src
RUN cargo build --release --locked \
    && mkdir -p /data

# Only the binary, for `docker build --target binary --output .`
FROM scratch AS binary
COPY --from=build /src/target/release/unlatch /unlatch

FROM scratch
COPY --from=build /src/target/release/unlatch /unlatch
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV UNLATCH_LISTEN=0.0.0.0:8080 \
    UNLATCH_DATABASE=/data/unlatch.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/unlatch"]
