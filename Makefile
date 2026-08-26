.PHONY: build start start-block test clean install uninstall

build:
	go build -o bin/hygienics .

start: build
	./bin/hygienics

start-block: build
	./bin/hygienics -mode block

test:
	go test ./...

clean:
	rm -rf bin

# launchd service: starts at login, restarts on crash
PLIST := $(HOME)/Library/LaunchAgents/local.hygienics.plist

install: build
	@printf '%s\n' \
	'<?xml version="1.0" encoding="UTF-8"?>' \
	'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	'<plist version="1.0"><dict>' \
	'  <key>Label</key><string>local.hygienics</string>' \
	'  <key>ProgramArguments</key><array><string>$(CURDIR)/bin/hygienics</string></array>' \
	'  <key>RunAtLoad</key><true/>' \
	'  <key>KeepAlive</key><true/>' \
	'  <key>StandardOutPath</key><string>$(HOME)/Library/Logs/hygienics.log</string>' \
	'  <key>StandardErrorPath</key><string>$(HOME)/Library/Logs/hygienics.log</string>' \
	'</dict></plist>' > $(PLIST)
	launchctl bootout gui/$$(id -u)/local.hygienics 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) $(PLIST)

uninstall:
	launchctl bootout gui/$$(id -u)/local.hygienics 2>/dev/null || true
	rm -f $(PLIST)
