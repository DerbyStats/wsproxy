
test:
	go test ./...

release:
	GOOS=linux GOARCH=amd64 go build -o wsproxy-linux-amd64
	GOOS=windows GOARCH=amd64 go build -o wsproxy-windows-amd64
	GOOS=darwin GOARCH=amd64 go build -o wsproxy-darwin-amd64
	rm -f wsproxy-binaries.zip
	zip wsproxy-binaries.zip wsproxy-linux-amd64 wsproxy-windows-amd64 wsproxy-darwin-amd64 config.ini

.Phony: test release


