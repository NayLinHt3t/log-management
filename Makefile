# Shortcuts; everything also works through ./run.sh or npm scripts.
.PHONY: up saas down reset logs status demo info install build test test-integration dev db

up:       ## build and start the appliance (creates .env on first run)
	./run.sh up
saas:     ## start with the SaaS overrides (DOMAIN + TLS_MODE=acme in .env)
	./run.sh saas
down:     ## stop, keep data
	./run.sh down
reset:    ## stop and delete all data
	./run.sh reset
logs:     ## follow logs of every service
	./run.sh logs
status:   ## container + API health
	./run.sh status
demo:     ## send all samples and a brute-force burst
	./run.sh demo
info:     ## print URL, logins and ingest key
	./run.sh info

install:  ## install dependencies for local development
	npm ci
build:    ## compile services and build the UI
	npm run build
test:     ## unit tests (+ integration tests when TEST_POSTGRES_URL is set)
	npm test
test-integration: ## start the dev database and run every test against it
	npm run db:up
	TEST_POSTGRES_URL=$${TEST_POSTGRES_URL:-postgres://logs:logs@localhost:5433/logs_test} npm test
db:       ## start only Postgres for local development
	npm run db:up
dev:      ## run backend, ingest, worker and the UI with hot reload (needs `make db`)
	npm run dev

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/ -/'
