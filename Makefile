.PHONY: build build-wgreal build-windows mobile-ios mobile-android test vet clean

BIN := bin
PKGS := ./...

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/ratelmeshd ./cmd/ratelmeshd
	go build -o $(BIN)/ratelmesh ./cmd/ratelmesh
	go build -o $(BIN)/ratelmesh-pqverify ./cmd/ratelmesh-pqverify

build-wgreal:
	mkdir -p $(BIN)
	go build -tags wgreal -o $(BIN)/ratelmeshd ./cmd/ratelmeshd

build-windows:
	mkdir -p $(BIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -tags wgreal -o $(BIN)/ratelmeshd-windows-amd64.exe ./cmd/ratelmeshd
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o $(BIN)/ratelmesh-windows-amd64.exe ./cmd/ratelmesh

mobile-ios:
	./clients/ios/Scripts/build-ratelmesh-mobile.sh

mobile-android:
	./clients/android/scripts/build-ratelmesh-mobile.sh

test:
	go test -race $(PKGS)

vet:
	go vet $(PKGS)
	go vet -tags wgreal $(PKGS)

clean:
	rm -rf $(BIN)
