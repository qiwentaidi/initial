GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_linux_amd64 main.go
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_linux_arm64 main.go

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_amd64.exe main.go
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_arm64.exe main.go

GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_darwin_amd64 main.go
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-w -s" -o release/initial_darwin_arm64 main.go
