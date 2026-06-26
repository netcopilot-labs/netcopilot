.PHONY: help up down install test seed

help:        ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

up:          ## start Neo4j (docker compose)
	docker compose up -d

down:        ## stop services (data persists)
	docker compose down

install:     ## install the package (editable, with dev deps)
	pip install -e ".[dev]"

test:        ## run the public test suite
	pytest -q

seed:        ## load the synthetic demo seed into Neo4j (needs Neo4j up + make install)
	python -m netcopilot.graph.loader
