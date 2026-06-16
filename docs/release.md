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
uv run --isolated --with dist/snulbug-*.whl snulbug --help
uv run --isolated --with dist/snulbug-*.whl python -m snulbug --help
```

4. Inspect the distributions:

```bash
tar -tzf dist/snulbug-*.tar.gz | sed -n '1,120p'
python -m zipfile -l dist/snulbug-*.whl
```

5. Confirm the README long description uses absolute image URLs or package
   assets that will render on PyPI.
6. Configure trusted publishing for both GitHub environments:
   - `testpypi` on TestPyPI for release-candidate checks.
   - `pypi` on PyPI for the final release.
7. Run the manual `Publish` workflow with `repository = testpypi`.
8. Install from TestPyPI in a clean environment and smoke test:

```bash
uvx --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ snulbug --help
```

9. Run the manual `Publish` workflow with `repository = pypi` when the TestPyPI
   install and smoke test succeed.
10. Create the GitHub release and tag after the PyPI package is available.
