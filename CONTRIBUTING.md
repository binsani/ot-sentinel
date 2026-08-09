# Contributing

Open an issue before substantial changes. Never test against a production OT network without the asset owner's written authorization and an approved safety plan. Contributions must preserve passive-by-default behavior, include tests, and update the compliance mapping when behavior changes.

Install `uv`, then run `uv sync --frozen --extra dev`. From `backend/`, run `uv run ruff check
.`, `uv run mypy app`, and `uv run pytest`. From `sensor/`, run `uv run ruff check .` and `uv run
pytest` before opening a pull request.
