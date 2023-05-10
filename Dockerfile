FROM rust:1.69

WORKDIR /usr/src/dprio
COPY Cargo.toml Cargo.toml
COPY src src
COPY examples examples
RUN cargo build --release --example comparison
ENTRYPOINT ["cargo", "run", "--release", "--example", "comparison"]
CMD []
