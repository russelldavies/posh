#!/bin/sh

GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o posh_linux_amd64 posh.go
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o posh_linux_armv8 posh.go
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o posh_linux_armv7 posh.go

upx --brute posh_linux_*
