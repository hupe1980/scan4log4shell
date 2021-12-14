PROJECTNAME=$(shell basename "$(PWD)")

# Go related variables.
# Make is verbose in Linux. Make it silent.
MAKEFLAGS += --silent

.PHONY: help
## help: Prints this help message
help: Makefile
	@echo
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

.PHONY: setup
## setup: Setup installes dependencies
setup:
	@go mod tidy

.PHONY: test
## test: Runs go test with default values
test: 
	@go test -v -race -count=1  ./...

.PHONY: run
run:
	@go run *.go -cidr 127.0.0.1/32 --caddr :4444 --listen

.PhONY: run-test
run-test:
	@docker-compose up --build