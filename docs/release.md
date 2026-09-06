# Release process

1. Finalize `CHANGELOG.md`, with a dated release section and upgrade notes. Keep
   protocol preview limitations distinct from package release readiness.
2. Bump `version` in `pyproject.toml` and `snulbug/__init__.py`, update the
   devcontainer feature manifest and its docs/example references, and run `uv lock`.
3. Run verification:

```bash
uv run snulbug release-qa
```

The release QA suite runs:

- version consistency across package metadata, `uv.lock`, and the devcontainer feature
- README image URL checks for PyPI rendering
- `ruff format --check`
- `ruff check`
- Bandit high-severity scan
- pytest with bytecode disabled
- `uv build`
- distribution inspection for protocol modules, schema fixtures and their license, and cache artifacts
- source CLI/module smoke tests
- isolated built-wheel CLI/module smoke tests outside the source checkout
- installed-wheel protocol discovery and offline JSON Schema 2020-12 checks

These checks do not certify client/provider E2E interoperability. For 0.2.0,
2025-11-25 remains the default and 2026-07-28 remains an opt-in preview.

Before publishing, include all new modules, docs, tests, and fixtures in the
release commit and require green CI on Python 3.10, 3.11, 3.12, and 3.13. Local
QA alone does not establish the remote CI result. Publish both indexes from the
same reviewed commit; do not move the branch between TestPyPI and PyPI runs.

4. Optionally inspect the distributions by hand:

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
uvx --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ snulbug==0.2.0 --help
```

9. Run the manual `Publish` workflow with `repository = pypi` when the TestPyPI
   install and smoke test succeed.
10. Create the GitHub release and tag after the PyPI package is available.

The `Publish` workflow uses `workflow_dispatch`, not a tag trigger. Creating or
pushing `v0.2.0` does not publish a package or automatically create a GitHub release.
