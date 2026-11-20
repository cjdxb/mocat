.PHONY: build test vet package fake clean

build:
	CGO_ENABLED=0 go build -o bin/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

# 构建 amd64/arm64 发行包（需要 third_party/bin/<arch>/fakehttp,fakesip，或 BUILD_FAKE=1 自动用 docker 编译）
package:
	bash scripts/package.sh

fake:
	sh scripts/build-fake.sh amd64 third_party/bin/amd64
	sh scripts/build-fake.sh arm64 third_party/bin/arm64

clean:
	rm -rf bin dist
