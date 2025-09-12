'''
Tyler Hudgins
9/10/2025
vector_preprocessing.py

This script preprocesses Cybersecurity GRC PDFs:
1. Extracts text from PDFs in 'data' directory and saves them as Document objects
2. Saves chunks from each PDF as a JSON file for summary 
3. Embeds Documents in ChromaDB for vector search
4. Extracts entities/relations between Documents and stores them in Neo4j as a knowledge graph
'''

import os
import json
from tqdm import tqdm
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain.prompts import PromptTemplate
from langchain_chroma import Chroma
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
import asyncio
from tqdm.asyncio import tqdm_asyncio
from neo4j import GraphDatabase
from dotenv import load_dotenv
load_dotenv()

# Set OpenAI API key from environment variable
os.environ['OPENAI_API_KEY'] = os.getenv('OPENAI_API_KEY')

def load_pdfs(directory_path):
    '''
    Loads all PDF files from the specified directory, extracts text,
    and returns a list of langchain Document objects with metadata.
    
    Args:
        directory_path: Path to the directory containing PDF files
        
    Returns: List of Document objects
    '''
    # List all PDF files in the directory
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith('.pdf')]
    
    # Initialize list to hold Document objects
    documents = []
    
    # Process each PDF file
    for pdf_file in tqdm(pdf_files, desc="Loading PDFs"):
        # Read PDF file
        reader = PdfReader(os.path.join(directory_path, pdf_file))
        
        # Extract text from all pages
        text = "".join([page.extract_text() or "" for page in reader.pages])
        
        # Create Document object with metadata and appends to documents list
        doc = Document(page_content=text, metadata={"source": pdf_file})
        documents.append(doc)
    
    # Return list of Document objects
    return documents



def save_documents_as_json(documents, output_dir="json_docs", chunk_size=1000, chunk_overlap=100):
    """
    Chunks each of the given Documents and then saves all 
    chunks for each Document in a given JSON file.

    Args:
        documents: List of langchain Document objects (with metadata)
        output_dir: Directory to save JSON files
        chunk_size: Size of each text chunk
        chunk_overlap: Overlap between chunks

    Returns: None but saves JSON files to disk
    """
    # Ensure output directory exists and creates directory if not
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize text splitter
    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    
    # Process each Document
    for doc in tqdm(documents, desc="Chunking and saving PDFs as JSON"):
        # Split document into chunks
        chunks = splitter.split_documents([doc])
        
        # Format chunks for JSON output
        formatted_chunks = []
        
        # Add chunk index and metadata to each chunk
        for idx, chunk in enumerate(chunks):
            formatted_chunks.append({
                "chunk_id": idx,
                "content": chunk.page_content,
                "metadata": {
                    "source": doc.metadata["source"],
                    "chunk_index": idx
                }
            })
        
        # Save chunks to a JSON file named after the original PDF
        out_path = os.path.join(output_dir, f"{os.path.splitext(doc.metadata['source'])[0]}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(formatted_chunks, f, indent=2, ensure_ascii=False)
        
        # Log the save operation
        print(f"Saved {len(formatted_chunks)} chunks for {doc.metadata['source']} → {out_path}")


def save_to_chromadb(documents):
    """
    Embed documents using Ollama nomic-embed-text and store in a ChromaDB.

    Args:
        documents: List of Documents 
    
    Returns: None but saves to ChromaDB
    """
    # Initialize Ollama Embeddings model
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-large")
    
    # Create Chroma vector store with precomputed embeddings
    vectordb = Chroma(
        collection_name="Cybersecurity_Frameworks",
        embedding_function=embeddings_model,
        persist_directory=".chromadb/"
    )

    # Log the embedding operation
    print("Embedding documents with OpenAI text-embedding...")

    # Embed and add documents to the ChromaDB vector store at .chromadb/ directory
    vectordb.add_documents(
        documents=documents,
    )

    print("Embedded all documents into ChromaDB successfully.")

async def process_chunk(doc, chain):
    """Process a single chunk asynchronously and return structured triples."""
    prompt_input = {"text": doc.page_content}
    response = await chain.ainvoke(prompt_input)
    return {"source": doc.metadata["source"], "triples": response}

async def extract_relations_async(documents, max_concurrent=20):
    """
    Extract entities and relationships from documents asynchronously.

    Args:
        documents: List of Document objects
        max_concurrent: Number of parallel LLM requests
    Returns:
        List of triples per document
    """
    # Initialize GPT-5 Mini
    llm = ChatOpenAI(model="gpt-5-mini")
    
    # Define prompt template for JSON output
    prompt = PromptTemplate(
        input_variables=["text"],
        template="""
        Extract entities and relationships from the text below.
        Return a JSON array of triples in this format:
        [{"entity1": "...", "relation": "...", "entity2": "..."}]

        Text:
        {text}
        """
    )

    chain = prompt | llm

    # Process chunks in batches to limit concurrency
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def sem_task(doc):
        async with semaphore:
            return await process_chunk(doc, chain)

    tasks = [sem_task(doc) for doc in documents]
    for res in tqdm_asyncio.as_completed(tasks, desc="Extracting triples"):
        results.append(await res)
    
    return results


# Input: list of triples
# Output: None but knowledge graph is stored in Neo4j
def save_to_neo4j(triples_list):
    # Use global driver
    with driver.session() as session:
        
        # Process each entry in triples list
        for entry in triples_list:
            
            # Parse triples and create nodes/relationships in Neo4j
            for line in entry["triples"].split("\n"):
                if "->" in line:
                    try:
                        parts = line.strip().split("->")
                        entity1 = parts[0].split(")")[0].strip("() ")
                        relation = parts[0].split("]")[0].split("[")[-1].strip()
                        entity2 = parts[1].strip("() ")

                        if entity1 and entity2 and relation:
                            session.run(
                                """
                                MERGE (a:Entity {name: $entity1})
                                MERGE (b:Entity {name: $entity2})
                                MERGE (a)-[r:RELATION {type: $relation}]->(b)
                                """,
                                entity1=entity1,
                                entity2=entity2,
                                relation=relation,
                            )
                    except Exception:
                        continue

    # Log the Neo4j storage operation
    print("Knowledge graph stored in Neo4j.")


# -----------------------
# Main Pipeline
# -----------------------
if __name__ == "__main__":
    # Initialize data directory
    data_directory = "data"

    # Load PDFs
    documents = load_pdfs(data_directory)

    # Save document chunks as JSON files
    #save_documents_as_json(documents, output_dir="json_docs")

    # Chunk documents 
    chunked_documents = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100).split_documents(documents)

    # Embed and store in ChromaDB
    #save_to_chromadb(chunked_documents)

    # Configure Neo4j connection (change credentials as needed)
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD') 
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)) 

    print("Extracting knowledge graph and storing in Neo4j...")
    triples = asyncio.run(extract_relations_async(chunked_documents))
    save_to_neo4j(triples)
    driver.close()

    print("All preprocessing complete.")
