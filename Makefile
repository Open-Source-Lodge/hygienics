.PHONY: build start start-block test lint clean install uninstall

build:
	go build -o bin/hygienics ./cmd/hygienics

start: build
	./bin/hygienics

start-block: build
	./bin/hygienics -mode block

test:
	go test ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -rf bin

# Service: launchd on macOS, systemd user unit on Linux.
# Starts at login, restarts on crash.
PLIST := $(HOME)/Library/LaunchAgents/local.hygienics.plist
UNIT := $(HOME)/.config/systemd/user/hygienics.service

ifeq ($(shell uname),Darwin)
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
else
install: build
	@mkdir -p $(dir $(UNIT))
	@printf '%s\n' \
	'[Unit]' \
	'Description=hygienics secret-redacting proxy for Claude Code' \
	'' \
	'[Service]' \
	'ExecStart=$(CURDIR)/bin/hygienics' \
	'Restart=always' \
	'' \
	'[Install]' \
	'WantedBy=default.target' > $(UNIT)
	systemctl --user daemon-reload
	systemctl --user enable --now hygienics
	systemctl --user restart hygienics

uninstall:
	systemctl --user disable --now hygienics 2>/dev/null || true
	rm -f $(UNIT)
	systemctl --user daemon-reload
endif
