"""Build / load the Chroma collection of framework chunks.

Run as a script to (re)build the index:

    python -m auditor.ingest.frameworks_index --rebuild
"""
from __future__ import annotations

import argparse
import logging

from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from tqdm import tqdm

from auditor.config import settings
from auditor.ingest.pdf_loader import chunk_documents, load_all_pdfs

log = logging.getLogger(__name__)


def get_embeddings() -> OpenAIEmbeddings:
    return OpenAIEmbeddings(
        model=settings.embedding_model,
        api_key=settings.openai_api_key,
    )


def get_vectorstore() -> Chroma:
    return Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(),
        persist_directory=str(settings.chroma_dir),
    )


def build_index(batch_size: int = 100) -> int:
    settings.chroma_dir.mkdir(parents=True, exist_ok=True)

    pages = load_all_pdfs()
    print(f"Loaded {len(pages)} pages from {settings.data_dir}.")

    chunks = chunk_documents(pages)
    print(f"Split into {len(chunks)} chunks (size={settings.chunk_size}, overlap={settings.chunk_overlap}).")

    store = get_vectorstore()
    for i in tqdm(range(0, len(chunks), batch_size), desc="Embedding"):
        store.add_documents(chunks[i : i + batch_size])

    print(f"Wrote {len(chunks)} chunks to collection '{settings.chroma_collection}'.")
    return len(chunks)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rebuild", action="store_true", help="Build the index from PDFs.")
    parser.add_argument("--probe", type=str, default=None, help="Run a sanity retrieval for the given query.")
    args = parser.parse_args()

    if args.rebuild:
        build_index()

    if args.probe:
        store = get_vectorstore()
        results = store.similarity_search(args.probe, k=5)
        for r in results:
            print(f"[{r.metadata.get('framework')} p.{r.metadata.get('page')}] {r.page_content[:200]}...")


if __name__ == "__main__":
    main()
