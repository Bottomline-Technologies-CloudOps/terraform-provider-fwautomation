TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=registry.terraform.io
NAMESPACE=BT-CloudOps
NAME=fwautomation
BINARY=terraform-provider-${NAME}
VERSION=1.3.27
OS_ARCH=linux_amd64

default: install

build:
	go build -o ${BINARY}

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -o ./bin/${BINARY}_${VERSION}_darwin_arm64
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	GOOS=freebsd GOARCH=arm64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm64
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm
	GOOS=linux GOARCH=arm64 go build -o ./bin/${BINARY}_${VERSION}_linux_arm64
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64

package: build
	mkdir -p ./binaries
	mv ${BINARY} ./binaries/${BINARY}

install: build
	mkdir -p ~/.local/share/terraform/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.local/share/terraform/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m
