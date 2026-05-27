#!/bin/sh
set -e

if [ ! -f .chromadb/chroma.sqlite3 ]; then
    echo "First-time setup: fetching OWASP markdown + embedding all sources (~2-3 min, ~\$0.15 of OpenAI credits)..."
    python -m auditor.ingest.frameworks_index --fetch-web --rebuild
fi

# Pre-warm the MITRE ATT&CK STIX cache (~20MB) so the first audit isn't delayed.
# Non-fatal: if the download fails we'll fall back to the curated keyword map.
if [ ! -f "${HOME}/.cache/auditor/attack_techniques.json" ]; then
    echo "Pre-fetching MITRE ATT&CK STIX bundle (one-time, ~20MB)..."
    python -c "from auditor.enrichment.mitre import _load_stix_techniques; _load_stix_techniques()" || true
fi

exec streamlit run app.py \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --server.headless=true
