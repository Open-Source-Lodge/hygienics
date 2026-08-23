.PHONY: build start start-block test clean

build:
	go build -o hygienics .

start: build
	./hygienics

start-block: build
	./hygienics -mode block

test:
	go test ./...

clean:
	rm -f hygienics
