#
# (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
#

env GOOS=windows GOARCH=amd64 go build -ldflags="-X eolh/cmd/cmd.version=\"v0.0.1beta1\"" -o eolh.exe cmd/main.go
