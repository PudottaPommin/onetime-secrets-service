set windows-shell := ["pwsh.exe", "-c"]

check:
    go vet ./...

fmt:
    go fmt ./...
    go tool goimports -w .

update:
  go get -u ./...
  go mod tidy -v

dev:
     go tool wgo -file=".gohtml" -file=".go" go run ./cmd/main.go

[windows]
build:
    go build -trimpath -o ./server.exe ./cmd/server.exe

release:
    goreleaser release --clean
    docker buildx build --platform=linux/amd64,linux/arm64 -t ghcr.io/pudottapommin/onetime-secrets-service:$(git describe --tags --abbrev=0) .
