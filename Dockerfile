FROM --platform=${BUILDPLATFORM} gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
USER nonroot:nonroot
COPY $TARGETPLATFORM/server /usr/bin
ENV OSS_SERVER_ADDR="0.0.0.0:8080"
EXPOSE 8080
ENTRYPOINT ["/usr/bin/server"]