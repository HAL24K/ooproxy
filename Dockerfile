FROM alpine:3.9 AS build
ARG features=tls
RUN apk add openssl-dev rust cargo
COPY . .
RUN cargo test --all-features
RUN cargo build --release --features="$features"
RUN mv /target/release/ooproxy .
RUN strip --strip-all ooproxy

FROM alpine:3.9
ARG features=tls
RUN if [ "$features" = "tls" ] ; then apk add openssl libgcc ; else apk add libgcc ; fi
COPY --from=build /ooproxy /
ENTRYPOINT ["/ooproxy"]