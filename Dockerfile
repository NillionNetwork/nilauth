FROM rust:1.85-alpine AS build

WORKDIR /opt/nillion

RUN apk add --no-cache musl-dev git

COPY . .

RUN cargo build --release --locked

FROM scratch

WORKDIR /opt/nillion

COPY --from=build /opt/nillion/target/release/nilauth /opt/nillion

ENTRYPOINT ["/opt/nillion/nilauth"]

