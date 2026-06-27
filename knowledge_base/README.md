# Your vendor documents (RAG)

Drop vendor PDFs here (configuration guides, hardening docs), then ingest them so
the agent can cite them:

```bash
docker compose exec dashboard \
  python -m netcopilot.rag.ingest --docs-dir /app/knowledge_base
```

This folder ships empty on purpose (so a fresh clone owns it); your PDFs here are
gitignored and never leave your machine.
