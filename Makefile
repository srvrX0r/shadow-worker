# Shadow Worker - Makefile
# Defensive Security Operations Framework

.PHONY: help install dev test lint format clean run scan ci docker-build

# Default target
help:
	@echo "Shadow Worker - Defensive Security Operations Framework"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Setup:"
	@echo "  install      Install Shadow Worker"
	@echo "  dev          Install with development dependencies"
	@echo "  init         Initialize configuration"
	@echo ""
	@echo "Development:"
	@echo "  test         Run tests"
	@echo "  lint         Run ruff"
	@echo "  ci           Lint and test (same gates as GitHub Actions)"
	@echo "  typecheck    Run type checker"
	@echo ""
	@echo "Usage:"
	@echo "  status       Show configuration status"
	@echo "  scan-sast    Run SAST scan on current directory"
	@echo "  scan-local   Run quick scan on localhost"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean        Clean build artifacts"
	@echo "  rules        Create default detection rules"

# Installation targets
install:
	pip install -e .

dev:
	pip install -e ".[dev]"

web3:
	pip install -e ".[web3]"

mobile:
	pip install -e ".[mobile]"

all-deps: dev web3 mobile

# Configuration
init:
	shadow init

rules:
	mkdir -p rules/yara rules/suricata rules/custom data
	@echo "Rules directories created"

# Development targets
test:
	pytest

lint:
	ruff check src tests

ci: lint test

format:
	ruff check --fix src tests

typecheck:
	mypy src/shadow_worker

# Usage targets
status:
	shadow status

scan-sast:
	shadow scan . --type sast

scan-local:
	shadow scan localhost --type quick

# Monitoring
monitor:
	shadow monitor --interval 3600

# Maintenance
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf __pycache__/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Container
docker-build:
	docker build -t shadow-worker:1.1.0 .

docker-run:
	docker run --rm shadow-worker:1.1.0 --help

# Documentation
docs:
	@echo "Documentation available in docs/"
	@echo "  - INSTALLATION.md"
	@echo "  - CLI_GUIDE.md"
	@echo "  - API_REFERENCE.md"
