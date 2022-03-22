
test:
	go test ./...

release:
	GOOS=linux GOARCH=amd64 go build -trimpath -o wsproxy-linux-amd64
	GOOS=windows GOARCH=amd64 go build -trimpath -o wsproxy-windows-amd64.exe
	GOOS=darwin GOARCH=amd64 go build -trimpath -o wsproxy-darwin-amd64
	rm -f wsproxy-binaries.zip
	zip wsproxy-binaries.zip wsproxy-linux-amd64 wsproxy-windows-amd64.exe wsproxy-darwin-amd64 config.ini

.Phony: test release


