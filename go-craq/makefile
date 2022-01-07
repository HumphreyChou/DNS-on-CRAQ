DIR=bin

.PHONY: all
all: server dhcp

server:
	go build -tags $(MODE) -o $(DIR)/server main/server/server.go

dhcp:
	go build -tags $(MODE) -o $(DIR)/dhcp main/dhcp/dhcp.go

.PHONY: clean
clean:
	rm -rf $(DIR)/*
	
# original CRAQ CLI tool module, not used
client-rpi:
	env GOOS=linux GOARCH=arm GOARM=7 go build -o bin/rpi/client cmd/client/client.go
node-rpi:
	env GOOS=linux GOARCH=arm GOARM=7 go build -o bin/rpi/node cmd/node/node.go
coordinator-rpi:
	env GOOS=linux GOARCH=arm GOARM=7 go build -o bin/rpi/coordinator cmd/coordinator/coordinator.go
