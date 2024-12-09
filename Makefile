include .env
export

src-dir = pqcow
tests-dir = tests
client-dir = $(src-dir)/client
server-dir = $(src-dir)/server
func-dir = $(src-dir)/func
types-dir = $(src-dir)/pq_types

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
	uv run ruff check --config pyproject.toml --diff $(src-dir) $(tests-dir)

.PHONY format:
format:
	echo "Running ruff check with --fix..."
	uv run ruff check --config pyproject.toml --fix --unsafe-fixes $(src-dir) $(tests-dir)

	echo "Running ruff..."
	uv run ruff format --config pyproject.toml $(src-dir) $(tests-dir)

	echo "Running isort..."
	uv run isort --settings-file pyproject.toml $(src-dir) $(tests-dir)

.PHONE mypy:
mypy:
	echo "Running MyPy..."
	uv run mypy --config-file pyproject.toml

.PHONY outdated:
outdated:
	uv tree --outdated --universal

.PHONY sync:
sync:
	uv sync --extra client --extra dev --extra lint --extra uvloop --link-mode=copy

.PHONY freeze: sync
freeze:
	uv export --quiet --format requirements-txt --no-dev --extra uvloop --output-file requirements.txt
