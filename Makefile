include .env
export

src-dir = packages
client-dir = $(src-dir)/pqcow_client
server-dir = $(src-dir)/pqcow_server
func-dir = $(src-dir)/pqcow_func
types-dir = $(src-dir)/pqcow_types

.PHONY up:
up:
	docker compose -f docker-compose.yml up -d --build --timeout 60

.PHONY down:
down:
	docker compose -f docker-compose.yml down --timeout 60

.PHONY pull:
pull:
	git pull origin master
	git submodule update --init --recursive

.PHONY lint:
lint:
	echo "Running ruff..."
	uv run ruff check --config pyproject.toml --diff $(src-dir)

.PHONY format:
format:
	echo "Running ruff check with --fix..."
	uv run ruff check --config pyproject.toml --fix --unsafe-fixes $(src-dir)

	echo "Running ruff..."
	uv run ruff format --config pyproject.toml $(src-dir)

	echo "Running isort..."
	uv run isort --settings-file pyproject.toml $(src-dir)

.PHONE mypy:
mypy:
	echo "Running MyPy..."
	uv run mypy --config-file pyproject.toml --package $(src-dir)

.PHONY show-outdated:
show-outdated:
	uv tree --outdated --universal

.PHONY uv-sync:
uv-sync:
	uv sync --extra dev --extra lint --extra uvloop --link-mode=copy

.PHONY uv-export: uv-sync
uv-export:
	uv export --quiet --format requirements-txt --no-dev --extra uvloop --output-file $(src-dir)\requirements.txt
