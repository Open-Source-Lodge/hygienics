.PHONY: build start start-block test clean

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
