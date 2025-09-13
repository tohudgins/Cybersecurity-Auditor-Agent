"""
Tyler Hudgins
9/12/2025
vector_preprocessing.py

Preprocesses Cybersecurity GRC PDFs:
1. Extracts text from PDFs in 'data' directory
2. Chunks each PDF and optionally saves as JSON
3. Embeds Documents in ChromaDB for vector search
4. Uses GPT-5-nano to extract entities/relations into Neo4j
5. Creates semantic similarity edges between chunks
"""

import os
import json
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
from openai import OpenAI

load_dotenv()

# -------------------------
# Configuration
# -------------------------
DATA_DIR = "data"
JSON_DIR = "json_docs"
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"
CHUNK_SIZE = 2000
CHUNK_OVERLAP = 200
SIMILARITY_THRESHOLD = 0.6

# Neo4j
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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

def save_documents_as_json(documents, output_dir=JSON_DIR):
    os.makedirs(output_dir, exist_ok=True)
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
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
    chunked_docs = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100).split_documents(documents)
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    vectordb.add_documents(chunked_docs)
    print(f"Embedded {len(chunked_docs)} documents into ChromaDB at {CHROMA_DIR}")

def get_embeddings(chunks):
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=[chunk.page_content for chunk in chunks]
    )
    return [item.embedding for item in response.data]

# -------------------------
# Entity & Relation Extraction (GPT-5-nano)
# -------------------------
def extract_entities_relations(chunk_text):
    prompt = f"""
    Extract cybersecurity-specific entities and relations from the following text.
    Return JSON with "entities" and "relations".
    
    Entities = list of {{"text": "...", "label": "..."}}
    Relations = list of {{"source": "...", "target": "...", "type": "..."}}

    Text:
    {chunk_text}
    """
    response = client.chat.completions.create(
        model="gpt-5-nano",
        messages=[
            {"role": "system", "content": "You are a cybersecurity knowledge graph builder."},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"}
    )
    result = json.loads(response.choices[0].message.content)

    entities = [(e["text"], e["label"]) for e in result.get("entities", [])]
    relations = result.get("relations", [])
    return entities, relations

# -------------------------
# Neo4j Integration
# -------------------------
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def store_chunk_in_graph(chunk_text, chunk_id, entities, relations):
    with driver.session() as session:
        session.run("MERGE (c:Chunk {id:$id}) SET c.text=$text", id=chunk_id, text=chunk_text)
        for entity, label in entities:
            session.run("MERGE (e:Entity {name:$name, label:$label})", name=entity, label=label)
            session.run(
                "MATCH (c:Chunk {id:$chunk_id}), (e:Entity {name:$name}) "
                "MERGE (c)-[:MENTIONS]->(e)",
                chunk_id=chunk_id, name=entity
            )
        for rel in relations:
            session.run(
                "MATCH (e1:Entity {name:$src}), (e2:Entity {name:$tgt}) "
                f"MERGE (e1)-[:{rel['type'].upper()}]->(e2)",
                src=rel['source'], tgt=rel['target']
            )

def create_semantic_similarity_edges(chunks, threshold=SIMILARITY_THRESHOLD):
    embeddings = get_embeddings(chunks)
    similarity_matrix = cosine_similarity(embeddings)
    for i in range(len(embeddings)):
        for j in range(i+1, len(embeddings)):
            if similarity_matrix[i][j] > threshold:
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
    documents = load_pdfs(DATA_DIR)
    chunked_docs = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP).split_documents(documents)

    # Step 1: Optional save to JSON
    save_documents_as_json(documents, output_dir=JSON_DIR)

    # Step 2: Optional embed into Chroma
    embed_to_chromadb(documents)

    # Step 3: Process chunks for entities & relations
    print("Processing chunks for entities and relations...")
    for idx, chunk in tqdm(enumerate(chunked_docs), desc="Neo4j ingestion"):
        entities, relations = extract_entities_relations(chunk.page_content)
        store_chunk_in_graph(chunk.page_content, idx, entities, relations)

    # Step 4: Create semantic similarity edges
    print("Creating semantic similarity relationships...")
    create_semantic_similarity_edges(chunked_docs)

    print("Preprocessing complete. ChromaDB + Neo4j graph ready.")
