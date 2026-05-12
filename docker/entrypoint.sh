#!/bin/sh
set -e

if [ ! -f .chromadb/chroma.sqlite3 ]; then
    echo "First-time setup: fetching OWASP markdown + embedding all sources (~2-3 min, ~\$0.15 of OpenAI credits)..."
    python -m auditor.ingest.frameworks_index --fetch-web --rebuild
fi

exec streamlit run app.py \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --server.headless=true
