FROM rust:1.85-slim-bullseye AS build

WORKDIR /opt/nillion

COPY . .

RUN cargo build --release --locked

FROM debian:bullseye-slim

WORKDIR /opt/nillion

COPY --from=build /opt/nillion/target/release/authority-service /opt/nillion

ENTRYPOINT ["/opt/nillion/authority-service"]

