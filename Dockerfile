FROM --platform=${BUILDPLATFORM} golang:1.24.5-alpine AS build
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache upx
WORKDIR /app
COPY . .
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -trimpath -o server ./cmd/main.go
RUN upx --best --lzma ./server

FROM alpine
COPY --from=build /app/server /server
ENV OSS_HOST="0.0.0.0:8080"
ENTRYPOINT ["/server"]