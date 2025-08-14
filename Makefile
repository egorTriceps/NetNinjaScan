PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: install dev uninstall help build docker-build docker-run

help:
	@echo "Targets: install, dev, uninstall, build, docker-build, docker-run"

install:
	$(PIP) install .

dev:
	$(PIP) install -e .

uninstall:
	-$(PIP) uninstall -y svscan

build:
	$(PYTHON) -m build

docker-build:
	docker build -t svscan:latest .

docker-run:
	docker run --rm svscan:latest --help