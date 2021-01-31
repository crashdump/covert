build:
	go build -o dist/covert-darwin-arm  cmd/*.go

test:
	go fmt ./...
	go test -v ./... -coverprofile=coverage.out

coverage:
	go tool cover -html=coverage.out

release-test:
	goreleaser --snapshot --skip-publish --rm-dist