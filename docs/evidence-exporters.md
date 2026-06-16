# Evidence exporter plugins

Evidence exporters write review artifacts from `snulbug mcp evidence` results.
Built-ins:

- `markdown`: human-readable reports for `inspect`, `impact`, and `diff`
- `json`: machine-readable output for `record`, `replay`, `inspect`, `impact`,
  and `diff`
- `sarif`: Code Scanning output for `diff`

Use exporters directly from the CLI:

```bash
snulbug mcp evidence inspect traces/session.jsonl \
  --export markdown=traces/session-report.md \
  --export json=traces/session-report.json

snulbug mcp evidence diff active.lua candidate.lua fixtures/ \
  --export markdown=traces/policy-diff.md \
  --export sarif=traces/policy-diff.sarif
```

`--report-out` and `--sarif-out` are convenience wrappers around the same
exporter registry.

External exporters can register the same surface from Python:

```python
from snulbug import EvidenceExportContext, EvidenceExporter, register_evidence_exporter


class HtmlEvidenceExporter(EvidenceExporter):
    name = "html"
    commands = ("inspect", "impact", "diff")
    extension = ".html"

    def render(self, context: EvidenceExportContext) -> str:
        result = context.result
        return render_html_report(command=context.command, result=result)


register_evidence_exporter(HtmlEvidenceExporter(), replace=True)
```

An exporter receives:

- `context.command`: one of `record`, `replay`, `inspect`, `impact`, or `diff`
- `context.result`: the normalized command result
- `context.output`: the destination path
- `context.options`: optional exporter-specific options

Return `str` for text output or `bytes` for binary output. Keep exporter
metadata secret-safe; evidence results may contain redacted audit and replay
records intended for review.
