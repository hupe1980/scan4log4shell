PROJECTNAME=$(shell basename "$(PWD)")

# Go related variables.
# Make is verbose in Linux. Make it silent.
MAKEFLAGS += --silent

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
	@go run *.go remote url -h

.PHONY: run-local
run-local:
	@docker-compose -f docker-compose.local.yml up --build

.PhONY: run-remote
run-remote:
	@docker-compose -f docker-compose.remote.yml up --build

.PHONY: help
## help: Prints this help message
help: Makefile
	@echo
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo