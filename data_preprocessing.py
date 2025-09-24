'''
Tyler Hudgins
9/23/25
data_preprocessing.py

Data Preprocessing Pipeline for Cybersecurity Frameworks
This script processes PDF documents, splits them into manageable chunks,
saves the chunks in JSON files for each PDF, and embeds the chunks into a Chroma vector store for retrieval.
'''
import os
import json
import logging
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from dotenv import load_dotenv
from tqdm import tqdm

# Load environment variables from .env file
load_dotenv()

# Directory and File Configurations
DATA_DIR = "data"
JSON_DIR = "json_docs"
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"

# Chunking Parameters
RETRIEVAL_CHUNK_SIZE = 1000
RETRIEVAL_CHUNK_OVERLAP = 100

# OpenAI API Key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    filename='pipeline.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s'
)


'''
load_pdfs(directory_path: str) -> List[Document]
Description: Loads all PDFs from the specified directory and extracts text into Document objects.

@param directory_path: Path to the directory containing PDF files.
@return: List of Document objects with extracted text and metadata.
'''
def load_pdfs(directory_path : str):
    # Load all PDFs from the specified directory and extract text
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith(".pdf")]
    print(f"Found {len(pdf_files)} PDF files in {directory_path}.")
    documents = []
    print("Loading and extracting text from PDFs...")
    # Use tqdm for progress bar
    for pdf_file in tqdm(pdf_files, desc="Loading PDFs"):
        try:
            # Extract text from each PDF
            reader = PdfReader(os.path.join(directory_path, pdf_file))
            text = "".join([page.extract_text() or "" for page in reader.pages])
            if(pdf_file == 'CompTIA_Security+.pdf'):
                print(pdf_file)
                print(text)
            # Only add non-empty documents
            if text:
                documents.append(Document(page_content=text, metadata={"source": pdf_file}))
        except Exception as e:
            logging.error(f"Error reading {pdf_file}: {e}")
    # Return the list of Document objects
    return documents


'''
save_chunks_as_json(chunks: List[Document], output_dir: str = JSON_DIR)
Description: Saves the text content and metadata of each chunk into JSON files.

@param chunks: List of Document objects representing text chunks.
@param output_dir: Directory to save the JSON files.
@return: None
'''
def save_chunks_as_json(chunks, output_dir=JSON_DIR):
    # Save chunks as JSON files
    os.makedirs(output_dir, exist_ok=True)
    print("Saving retrieval-sized chunks to JSON files...")
    # Group chunks by their source document
    docs_to_chunks = {}
    for chunk in chunks:
        # Use source metadata to group chunks
        source = chunk.metadata.get("source", "unknown_source")
        if source not in docs_to_chunks:
            docs_to_chunks[source] = []
        # Append chunk to the corresponding source list
        docs_to_chunks[source].append(chunk)

    # Save each group of chunks to a separate JSON file
    for source, chunk_list in tqdm(docs_to_chunks.items(), desc="Saving JSON"):
        chunks_data = []
        # Create a unique ID for each chunk
        for i, chunk in enumerate(chunk_list):
            chunks_data.append({
                "chunk_id": f"{source}_chunk_{i}",
                "content": chunk.page_content,
                "metadata": chunk.metadata
            })
        # Write to JSON file
        filename = f"{os.path.splitext(source)[0]}.json"
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(chunks_data, f, indent=2, ensure_ascii=False)

'''
embed_to_chromadb(chunks: List[Document])
Description: Creates embeddings for the text chunks and stores them in a Chroma vector store.

@param chunks: List of Document objects representing text chunks.
@return: None
'''            
def embed_to_chromadb(chunks):
    # Embed chunks into ChromaDB
    os.makedirs(CHROMA_DIR, exist_ok=True)
    print("Embedding retrieval-sized chunks into ChromaDB...")
    # Initialize ChromaDB with OpenAI embeddings
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small", api_key=OPENAI_API_KEY)
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    # Add documents in batches to avoid memory issues
    batch_size = 100 
    for i in tqdm(range(0, len(chunks), batch_size), desc="Adding to ChromaDB"):
        batch = chunks[i:i+batch_size]
        vectordb.add_documents(batch)
    print("ChromaDB vector store is ready.")

# --- Main Execution ---
if __name__ == "__main__":
        # Load PDFs and extract text
        documents = load_pdfs(DATA_DIR)

        # Split documents into retrieval-sized chunks
        retrieval_splitter = RecursiveCharacterTextSplitter(
            chunk_size=RETRIEVAL_CHUNK_SIZE, chunk_overlap=RETRIEVAL_CHUNK_OVERLAP
        )

        # Create chunks for retrieval
        chunks_for_retrieval = retrieval_splitter.split_documents(documents)
        print(f"Created {len(chunks_for_retrieval)} chunks for retrieval/JSON.")

        # Save chunks as JSON and embed into ChromaDB
        save_chunks_as_json(chunks_for_retrieval)
        embed_to_chromadb(chunks_for_retrieval)