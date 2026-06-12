# Release process

1. Update `CHANGELOG.md`.
2. Bump `version` in `pyproject.toml` and `snulbug/__init__.py`.
3. Run verification:

```bash
uv run ruff format --check .
uv run ruff check .
uv run bandit -r snulbug -lll
PYTHONDONTWRITEBYTECODE=1 uv run pytest
uv build
uv run snulbug --help
uv run python -m snulbug --help
```

4. Inspect the distributions:

```bash
tar -tzf dist/snulbug-*.tar.gz | sed -n '1,120p'
python -m zipfile -l dist/snulbug-*.whl
```

5. Publish to TestPyPI first for release candidates.
6. Publish to PyPI when the TestPyPI install and smoke test succeed.
7. For GitHub releases, configure PyPI trusted publishing for the `pypi` environment and run the manual `Publish` workflow.
