import os
import json
import asyncio
import logging
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

# -------------------------
# Configuration & Setup
# -------------------------
# --- Directories and Constants ---
DATA_DIR = "data"
JSON_DIR = "json_docs"
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"

# --- Chunking Configurations ---
RETRIEVAL_CHUNK_SIZE = 1000
RETRIEVAL_CHUNK_OVERLAP = 100

# --- API and Database Credentials ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    filename='pipeline.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -------------------------
# PDF Loading and JSON/ChromaDB steps
# -------------------------
def load_pdfs(directory_path):
    """Loads all PDFs and extracts text into Document objects."""
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith(".pdf")]
    documents = []
    print("Loading and extracting text from PDFs...")
    for pdf_file in tqdm(pdf_files, desc="Loading PDFs"):
        try:
            reader = PdfReader(os.path.join(directory_path, pdf_file))
            text = "".join([page.extract_text() or "" for page in reader.pages])
            if text:
                documents.append(Document(page_content=text, metadata={"source": pdf_file}))
        except Exception as e:
            logging.error(f"Error reading {pdf_file}: {e}")
    return documents

def save_chunks_as_json(chunks, output_dir=JSON_DIR):
    """Saves the content and metadata of each chunk into JSON files."""
    os.makedirs(output_dir, exist_ok=True)
    print("Saving retrieval-sized chunks to JSON files...")
    docs_to_chunks = {}
    for chunk in chunks:
        source = chunk.metadata.get("source", "unknown_source")
        if source not in docs_to_chunks:
            docs_to_chunks[source] = []
        docs_to_chunks[source].append(chunk)

    for source, chunk_list in tqdm(docs_to_chunks.items(), desc="Saving JSON"):
        chunks_data = []
        for i, chunk in enumerate(chunk_list):
            chunks_data.append({
                "chunk_id": f"{source}_chunk_{i}",
                "content": chunk.page_content,
                "metadata": chunk.metadata
            })
        filename = f"{os.path.splitext(source)[0]}.json"
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(chunks_data, f, indent=2, ensure_ascii=False)

def embed_to_chromadb(chunks):
    """Creates embeddings and stores them in a Chroma vector store."""
    print("Embedding retrieval-sized chunks into ChromaDB...")
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small", api_key=OPENAI_API_KEY)
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    batch_size = 100 
    for i in tqdm(range(0, len(chunks), batch_size), desc="Adding to ChromaDB"):
        batch = chunks[i:i+batch_size]
        vectordb.add_documents(batch)
    print("ChromaDB vector store is ready.")

# -------------------------
# Run the pipeline
# -------------------------
if __name__ == "__main__":
        documents = load_pdfs(DATA_DIR)

        retrieval_splitter = RecursiveCharacterTextSplitter(
            chunk_size=RETRIEVAL_CHUNK_SIZE, chunk_overlap=RETRIEVAL_CHUNK_OVERLAP
        )
        chunks_for_retrieval = retrieval_splitter.split_documents(documents)
        print(f"Created {len(chunks_for_retrieval)} chunks for retrieval/JSON.")
        save_chunks_as_json(chunks_for_retrieval)
        embed_to_chromadb(chunks_for_retrieval)