all: linux osx windows

docker: linux Dockerfile
	docker build -t kibanaproxy:$(shell cat VERSION) .

linux: build/linux-amd64/kibanaproxy

osx: build/osx-amd64/kibanaproxy

windows: build/win-amd64/kibanaproxy.exe

# Linux Build
build/linux-amd64/kibanaproxy: main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $@ github.com/waucka/kibanaproxy
# OS X Build
build/osx-amd64/kibanaproxy: main.go
	GOOS=darwin GOARCH=amd64 go build -o $@ github.com/waucka/kibanaproxy
# Windows Build
build/win-amd64/kibanaproxy.exe: main.go
	GOOS=windows GOARCH=amd64 go build -o $@ github.com/waucka/kibanaproxy

clean:
	rm -f build/linux-amd64/kibanaproxy
	rm -f build/osx-amd64/kibanaproxy
	rm -f build/win-amd64/kibanaproxy.exe
	rm -f *~

.PHONY: all clean linux osx windows docker
