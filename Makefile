.PHONY: build build-wgreal build-windows mobile-ios mobile-android release-ios release-android test vet clean run-coord

BIN := bin
PKGS := ./...

build:
	go build -o $(BIN)/ratelmesh-coord ./cmd/ratelmesh-coord
	go build -o $(BIN)/ratelmeshd ./cmd/ratelmeshd
	go build -o $(BIN)/ratelmesh ./cmd/ratelmesh

# Real WireGuard data plane. Requires `wireguard-go` and `wg` on PATH at runtime
# and elevated privileges to create the TUN device.
build-wgreal:
	go build -tags wgreal -o $(BIN)/ratelmeshd ./cmd/ratelmeshd

build-windows:
	mkdir -p $(BIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -tags wgreal -o $(BIN)/ratelmeshd-windows-amd64.exe ./cmd/ratelmeshd
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o $(BIN)/ratelmesh-windows-amd64.exe ./cmd/ratelmesh

mobile-ios:
	./clients/ios/Scripts/build-ratelmesh-mobile.sh

mobile-android:
	./clients/android/scripts/build-ratelmesh-mobile.sh

release-ios:
	@test -n "$(VERSION)" || { echo "usage: make release-ios VERSION=X.Y.Z BUILD=N" >&2; exit 2; }
	@test -n "$(BUILD)" || { echo "usage: make release-ios VERSION=X.Y.Z BUILD=N" >&2; exit 2; }
	./clients/ios/Scripts/archive.sh "$(VERSION)" "$(BUILD)"

release-android:
	./clients/android/scripts/bundle-release.sh

test:
	go test $(PKGS)

vet:
	go vet $(PKGS)
	go vet -tags wgreal $(PKGS)

clean:
	rm -rf $(BIN)

run-coord: build
	$(BIN)/ratelmesh-coord -addr 127.0.0.1:8080
