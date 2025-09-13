import os
import json
import asyncio
import numpy as np
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from neo4j import AsyncGraphDatabase
from dotenv import load_dotenv
from sklearn.metrics.pairwise import cosine_similarity
from openai import AsyncOpenAI
from tqdm import tqdm

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
CONCURRENCY_LIMIT = 15  # GPT calls at once

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# Async OpenAI client
client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Neo4j async driver
driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Semaphore for GPT concurrency
sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

# -------------------------
# PDF Loading & Chunking
# -------------------------
def load_pdfs(directory_path):
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith(".pdf")]
    documents = []
    for pdf_file in tqdm(pdf_files, desc="Loading PDFs"):
        reader = PdfReader(os.path.join(directory_path, pdf_file))
        text = "".join([page.extract_text() or "" for page in reader.pages])
        documents.append(Document(page_content=text, metadata={"source": pdf_file}))
    return documents

def save_documents_as_json(documents, output_dir=JSON_DIR):
    os.makedirs(output_dir, exist_ok=True)
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    for doc in tqdm(documents, desc="Saving JSON chunks"):
        chunks = splitter.split_documents([doc])
        formatted_chunks = []
        for idx, chunk in enumerate(chunks):
            formatted_chunks.append({
                "chunk_id": idx,
                "content": chunk.page_content,
                "metadata": {"source": doc.metadata["source"], "chunk_index": idx}
            })
        out_path = os.path.join(output_dir, f"{os.path.splitext(doc.metadata['source'])[0]}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(formatted_chunks, f, indent=2, ensure_ascii=False)

# -------------------------
# Chroma Embeddings
# -------------------------
def embed_to_chromadb(documents):
    print("Embedding documents into ChromaDB...")
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    chunks = splitter.split_documents(documents)
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    vectordb.add_documents(chunks)
    # store embeddings in chunk metadata
    for i, chunk in enumerate(chunks):
        chunk.metadata['embedding'] = embeddings_model.embed_documents([chunk.page_content])[0]
    print(f"Embedded {len(chunks)} chunks into ChromaDB at {CHROMA_DIR}")
    return chunks

# -------------------------
# Async GPT-5-nano extraction
# -------------------------
async def extract_entities_relations_async(chunk_text):
    async with sem:
        prompt = f"""
        Extract cybersecurity-specific entities and relations from the following text.
        Return JSON with "entities" and "relations".

        Entities = list of {{"text": "...", "label": "..."}}
        Relations = list of {{"source": "...", "target": "...", "type": "..."}}

        Text:
        {chunk_text}
        """
        response = await client.chat.completions.create(
            model="gpt-5-nano",
            messages=[
                {"role": "system", "content": "You are a cybersecurity knowledge graph builder."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
        )
        result = json.loads(response.choices[0].message.content)
        entities = [(e["text"], e["label"]) for e in result.get("entities", [])]
        relations = result.get("relations", [])
        return entities, relations

# -------------------------
# Async Neo4j ingestion
# -------------------------
async def store_chunk_async(session, chunk_text, chunk_id, entities, relations):
    await session.run("MERGE (c:Chunk {id:$id}) SET c.text=$text", id=chunk_id, text=chunk_text)
    for entity, label in entities:
        await session.run("MERGE (e:Entity {name:$name, label:$label})", name=entity, label=label)
        await session.run(
            "MATCH (c:Chunk {id:$chunk_id}), (e:Entity {name:$name}) MERGE (c)-[:MENTIONS]->(e)",
            chunk_id=chunk_id, name=entity,
        )
    for rel in relations:
        await session.run(
            "MATCH (e1:Entity {name:$src}), (e2:Entity {name:$tgt}) "
            f"MERGE (e1)-[:{rel['type'].upper()}]->(e2)",
            src=rel["source"], tgt=rel["target"],
        )

async def ingest_chunks_async(chunks_with_entities):
    async with driver.session() as session:
        tasks = [
            store_chunk_async(session, chunk_text, idx, entities, relations)
            for idx, (chunk_text, entities, relations) in enumerate(chunks_with_entities)
        ]
        await asyncio.gather(*tasks)

# -------------------------
# Semantic similarity edges
# -------------------------
def create_similarity_edges(chunks, threshold=SIMILARITY_THRESHOLD):
    embeddings = [chunk.metadata['embedding'] for chunk in chunks]
    similarity_matrix = cosine_similarity(embeddings)
    async def insert_edges():
        async with driver.session() as session:
            for i in range(len(embeddings)):
                for j in range(i+1, len(embeddings)):
                    if similarity_matrix[i][j] > threshold:
                        await session.run(
                            "MATCH (c1:Chunk {id:$i}), (c2:Chunk {id:$j}) "
                            "MERGE (c1)-[:SIMILAR_TO {score:$score}]->(c2)",
                            i=i, j=j, score=float(similarity_matrix[i][j])
                        )
    asyncio.run(insert_edges())

# -------------------------
# Main pipeline
# -------------------------
def main_pipeline():
    documents = load_pdfs(DATA_DIR)

    # Step 1: Save JSON (optional)
    # save_documents_as_json(documents, output_dir=JSON_DIR)

    # Step 2: Embed into Chroma and get chunks with embeddings
    chunked_docs = embed_to_chromadb(documents)

    # Step 3: Extract entities/relations asynchronously
    print("Extracting entities and relations asynchronously...")
    async def extract_all():
        tasks = [extract_entities_relations_async(chunk.page_content) for chunk in chunked_docs]
        return await asyncio.gather(*tasks)
    extraction_results = asyncio.run(extract_all())

    chunks_with_entities = [
        (chunk.page_content, entities, relations)
        for chunk, (entities, relations) in zip(chunked_docs, extraction_results)
    ]

    # Step 4: Ingest into Neo4j
    print("Ingesting chunks into Neo4j...")
    asyncio.run(ingest_chunks_async(chunks_with_entities))

    # Step 5: Create similarity edges
    print("Creating similarity edges...")
    create_similarity_edges(chunked_docs)

    print("Pipeline complete. JSON + ChromaDB + Neo4j ready.")

# -------------------------
# Run pipeline
# -------------------------
if __name__ == "__main__":
    main_pipeline()
