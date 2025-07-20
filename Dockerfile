FROM --platform=${BUILDPLATFORM} golang:1.24.5-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY . .
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -trimpath -o server ./cmd/main.go

FROM alpine
COPY --from=build /app/server /server
ENV SECRET_SERVICE_HOST="0.0.0.0:8080"
ENTRYPOINT ["/server"]