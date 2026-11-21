# Reproducible builds: no cgo, trimmed paths, no VCS stamping, fixed version.
VERSION ?= 0.1.0
PKG      = github.com/theLabXHQ/subio
LDFLAGS  = -s -w -buildid= -X $(PKG)/internal/version.Version=$(VERSION)
GOFLAGS  = -trimpath -buildvcs=false
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build vet crosscheck dist clean
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o subio ./cmd/subio

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

# Vets every target platform, so a Unix-only call cannot break a build nobody
# made.
crosscheck:
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  printf '%-16s' "$$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go vet ./... || exit 1; \
	  echo "vet clean"; \
	done

dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o dist/subio_$(VERSION)_$${os}_$${arch}$$ext ./cmd/subio || exit 1; \
	done
	@cd dist && sha256sum subio_* > SHA256SUMS && cat SHA256SUMS

clean:
	rm -rf dist subio
