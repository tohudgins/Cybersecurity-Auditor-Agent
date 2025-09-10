'''
Tyler Hudgins
9/10/2025
vector_processing.py

This script takes Cybersecurity GRC PDF files from the data directory, extracts text, generates embeddings using Ollama, 
and stores them in a ChromaDB database for efficient RAG retrieval.
'''

from pypdf import PdfReader
import os
from chromadb import PersistentClient
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from tqdm import tqdm

# Load PDFs from the data directory and parse text and embed to a chroma DB database
def load_pdfs_from_directory(directory_path):

    # Initialize ChromaDB client
    client = PersistentClient(path=".chromadb/")

    # Create or get existing collection
    collection = client.get_or_create_collection(name="Cybersecurity_Frameworks")

    # Initialize OpenAI embeddings
    embeddings = OllamaEmbeddings(model="nomic-embed-text")

    documents = []

    pdf_files = [f for f in os.listdir(directory_path) if f.endswith('.pdf')]

    # Process each PDF in the directory
    for filename in tqdm(pdf_files, desc="Embedding PDFs"):
        if filename.endswith(".pdf"):
            file_path = os.path.join(directory_path, filename)
            reader = PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or ""

            doc = Document(page_content=text, metadata={"source": filename})
            documents.append(doc)
            
            # Embed and add to ChromaDB collection
    if documents:
        Chroma.from_documents(
        documents, 
        embeddings, 
        collection_name="Cybersecurity_Frameworks", 
        client=client
        )
            

    print("PDFs loaded and embedded into ChromaDB.")

if __name__ == "__main__":
    data_directory = "data"
    load_pdfs_from_directory(data_directory)
