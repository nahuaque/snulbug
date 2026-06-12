# Contributing

Thanks for considering a contribution to `snulbug`.

## Development setup

```bash
uv sync --extra dev
```

Run the checks used by CI:

```bash
uv run ruff format --check .
uv run ruff check .
PYTHONDONTWRITEBYTECODE=1 uv run pytest
uv build
```

## Pull requests

- Keep changes scoped to one behavior or public API surface.
- Add tests for new middleware behavior, simulator behavior, state adapters, or bundle validation rules.
- Update README or `docs/` when public behavior changes.
- Do not include generated caches, local databases, virtual environments, or build artifacts.

## Policy compatibility

Until `1.0`, `snulbug` is alpha software. Action schemas and trace fields may still change. When changing a public action or trace field, document the migration path in `CHANGELOG.md`.
