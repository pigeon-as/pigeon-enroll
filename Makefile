BINARY := pigeon-enroll
OUTDIR := build

.PHONY: build clean test vet

build:
	go build -o $(OUTDIR)/$(BINARY) ./cmd/pigeon-enroll

clean:
	rm -rf $(OUTDIR)

test:
	go test ./...

vet:
	go vet ./...
