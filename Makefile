VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/email-test-tools

.PHONY: all css build run dev test release clean

all: build

node_modules: package.json
	npm install
	@touch node_modules

## css: compile Tailwind + FlyonUI into web/static/assets/app.css
css: node_modules
	npm run build:css

## build: single self-contained binary (UI embedded)
build: css
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

## run: build and start, opening the browser
run: build
	./$(BIN)

## dev: rebuild CSS on change (run `go run .` in another terminal)
dev: node_modules
	npm run watch:css

test:
	go vet ./...
	go test ./...

## release: cross-compile for common platforms into dist/
release: css
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/email-test-tools-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/email-test-tools-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/email-test-tools-macos-intel .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/email-test-tools-macos-apple-silicon .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/email-test-tools-windows-amd64.exe .

clean:
	rm -rf bin dist
