#!/bin/sh
set -e

if [ ! -f .chromadb/chroma.sqlite3 ]; then
    echo "First-time setup: embedding framework PDFs (~1 min, ~\$0.05 of OpenAI credits)..."
    python -m auditor.ingest.frameworks_index --rebuild
fi

exec streamlit run app.py \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --server.headless=true
