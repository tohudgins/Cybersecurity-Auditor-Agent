"""
Tyler Hudgins
9/12/2025
vector_preprocessing.py

This script preprocesses Cybersecurity GRC PDFs:
1. Extracts text from PDFs in 'data' directory and saves them as Document objects
2. Chunks each PDF and optionally saves as JSON
3. Embeds Documents in ChromaDB for vector search
4. Extracts entities/relations between Documents and stores them in Neo4j as a knowledge graph
5. Creates semantic similarity edges between chunks
"""

import os
import json
import spacy
import numpy as np
from tqdm import tqdm
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from neo4j import GraphDatabase
from dotenv import load_dotenv
from sklearn.metrics.pairwise import cosine_similarity


load_dotenv()

# -------------------------
# Configuration
# -------------------------
DATA_DIR = "data"
JSON_DIR = "json_docs"
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 100
SIMILARITY_THRESHOLD = 0.7

# Neo4j Configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# Initialize NLP model
nlp = spacy.load("en_core_web_sm")

# Set OpenAI API key
os.environ['OPENAI_API_KEY'] = os.getenv('OPENAI_API_KEY')

# -------------------------
# PDF Loading & Chunking
# -------------------------
def load_pdfs(directory_path):
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith('.pdf')]
    documents = []
    for pdf_file in tqdm(pdf_files, desc="Loading PDFs"):
        reader = PdfReader(os.path.join(directory_path, pdf_file))
        text = "".join([page.extract_text() or "" for page in reader.pages])
        doc = Document(page_content=text, metadata={"source": pdf_file})
        documents.append(doc)
    return documents

def chunk_documents(documents):
    splitter = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)
    chunked_docs = splitter.split_documents(documents)
    return chunked_docs

def save_documents_as_json(documents, output_dir=JSON_DIR):
    os.makedirs(output_dir, exist_ok=True)
    splitter = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)
    for doc in tqdm(documents, desc="Chunking and saving PDFs as JSON"):
        chunks = splitter.split_documents([doc])
        formatted_chunks = []
        for idx, chunk in enumerate(chunks):
            formatted_chunks.append({
                "chunk_id": idx,
                "content": chunk.page_content,
                "metadata": {
                    "source": doc.metadata["source"],
                    "chunk_index": idx
                }
            })
        out_path = os.path.join(output_dir, f"{os.path.splitext(doc.metadata['source'])[0]}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(formatted_chunks, f, indent=2, ensure_ascii=False)

# -------------------------
# Chroma Embeddings
# -------------------------
def embed_to_chromadb(documents):
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    vectordb.add_documents(documents)
    print(f"Embedded {len(documents)} documents into ChromaDB at {CHROMA_DIR}")

# -------------------------
# Entity & Relation Extraction
# -------------------------
def extract_entities_relations(chunk_text):
    doc = nlp(chunk_text)
    entities = [(ent.text, ent.label_) for ent in doc.ents]
    relations = []
    for i in range(len(entities)-1):
        relations.append({
            "source": entities[i][0],
            "target": entities[i+1][0],
            "type": "co-occurrence"
        })
    return entities, relations

# -------------------------
# Neo4j Integration
# -------------------------
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def store_chunk_in_graph(chunk_text, chunk_id, entities, relations):
    with driver.session() as session:
        # Create chunk node
        session.run(
            "MERGE (c:Chunk {id:$id}) "
            "SET c.text=$text",
            id=chunk_id, text=chunk_text
        )
        # Create entity nodes and relationships
        for entity, label in entities:
            session.run(
                "MERGE (e:Entity {name:$name, label:$label})",
                name=entity, label=label
            )
            session.run(
                "MATCH (c:Chunk {id:$chunk_id}), (e:Entity {name:$name}) "
                "MERGE (c)-[:MENTIONS]->(e)",
                chunk_id=chunk_id, name=entity
            )
        # Add co-occurrence or custom relations
        for rel in relations:
            session.run(
                "MATCH (e1:Entity {name:$src}), (e2:Entity {name:$tgt}) "
                "MERGE (e1)-[:RELATED_TO]->(e2)",
                src=rel['source'], tgt=rel['target']
            )

def create_semantic_similarity_edges(embeddings):
    similarity_matrix = cosine_similarity(embeddings)
    for i in range(len(embeddings)):
        for j in range(i+1, len(embeddings)):
            if similarity_matrix[i][j] > SIMILARITY_THRESHOLD:
                with driver.session() as session:
                    session.run(
                        "MATCH (c1:Chunk {id:$i}), (c2:Chunk {id:$j}) "
                        "MERGE (c1)-[:SIMILAR_TO {score:$score}]->(c2)",
                        i=i, j=j, score=float(similarity_matrix[i][j])
                    )

# -------------------------
# Main Pipeline
# -------------------------
if __name__ == "__main__":
    # Load PDFs
    documents = load_pdfs(DATA_DIR)
    
    # Optional: Save chunked JSON files
    save_documents_as_json(documents, output_dir=JSON_DIR)
    
    # Chunk documents
    chunked_docs = chunk_documents(documents)
    
    # Embed in ChromaDB
    embed_to_chromadb(chunked_docs)
    
    # Extract entities/relations and store in Neo4j
    print("Processing chunks for entities and relations...")
    embeddings_list = []
    for idx, chunk in tqdm(enumerate(chunked_docs), desc="Neo4j ingestion"):
        entities, relations = extract_entities_relations(chunk.page_content)
        store_chunk_in_graph(chunk.page_content, idx, entities, relations)
        # Also collect embeddings for similarity edges
        embeddings_list.append(chunk.metadata.get("embedding", np.zeros(1536)))
    
    # Create semantic similarity edges in Neo4j
    print("Creating semantic similarity relationships...")
    create_semantic_similarity_edges(embeddings_list)
    
    print("Preprocessing complete. ChromaDB and Neo4j graph ready.")
