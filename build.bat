@echo off
go build -ldflags "-w -s" -o release/initial.exe main.go

@echo off
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build -ldflags "-w -s" -o release/initial_linux main.go

@echo off
SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
go build -ldflags "-w -s" -o release/initial_darwin main.go
