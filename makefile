tests:
	GO111MODULE=on go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...
tidy:
	GO111MODULE=on go mod tidy