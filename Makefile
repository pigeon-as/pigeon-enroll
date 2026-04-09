BINARY := pigeon-enroll
OUTDIR := build

.PHONY: build clean test vet e2e

build:
	mkdir -p $(OUTDIR)
	go build -o $(OUTDIR)/$(BINARY) ./cmd/pigeon-enroll

clean:
	rm -rf $(OUTDIR)

test:
	go test ./...

vet:
	go vet ./...

e2e: build
	go test -tags=e2e ./e2e -v
