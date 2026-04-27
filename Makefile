APP := v2ray-quick
CMD := ./cmd/v2ray-quick
GO ?= go
GOOS ?= linux
GOARCH ?= amd64

BUILD_FLAGS := -trimpath -buildvcs=false -tags netgo,osusergo
LD_FLAGS := -s -w

.PHONY: test build clean

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(BUILD_FLAGS) -ldflags '$(LD_FLAGS)' -o $(APP) $(CMD)

test:
	$(GO) test ./...

clean:
	rm -f $(APP)
