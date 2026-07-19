# MicroVM runner

The trusted runner accepts one allowlisted npm package per MicroVM, performs
static archive inspection, runs `npm install` under bounded resources, and
returns normalized JSON evidence. It has no AWS SDK and requires no AWS
credentials.

## Local usage

```bash
make fixtures
cd runner
uv sync
uv run package-inspector scan \
  --catalog ../fixtures/catalog.json \
  --package @demo/canary \
  --version 1.0.0 \
  --output ../reports/canary
```

On Linux, the runner automatically uses `strace`. On other operating systems,
it still collects static analysis, filesystem differences, bounded output, and
explicit canary evidence, while declaring syscall tracing unavailable.
