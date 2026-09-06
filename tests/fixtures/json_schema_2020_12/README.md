# JSON Schema Conformance Fixtures

Unmodified files from the MIT-licensed JSON-Schema-Test-Suite:
https://github.com/json-schema-org/JSON-Schema-Test-Suite/tree/c9510e3bf8a896c3cba4e08509cf752b4f30dff8/tests/draft2020-12

Pinned revision: `c9510e3bf8a896c3cba4e08509cf752b4f30dff8`.
The upstream license is included alongside these files.

The five dynamic-reference groups needing externally served schemas are explicitly
skipped by the runner. Snulbug intentionally provides no remote-schema retrieval;
separate tests prove HTTP and file references fail without I/O. All self-contained
groups run unchanged through snulbug's adapter, not directly through jsonschema.
This is a selected regression pack, not a claim to run the entire upstream suite.
