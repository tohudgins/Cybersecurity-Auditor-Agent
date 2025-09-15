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
from tqdm.asyncio import tqdm_asyncio
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
CONCURRENCY_LIMIT = 15  

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


# -------------------------
# Save documents as JSON
# -------------------------
def save_documents_as_json(documents, output_dir=JSON_DIR):
    chunks = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP).split_documents(documents)
    os.makedirs(output_dir, exist_ok=True)
    for idx, chunk in enumerate(tqdm(chunks, desc="Saving JSON chunks")):
        chunk_data = {
            "chunk_id": idx,
            "content": chunk.page_content,
            "metadata": {
                "source": chunk.metadata.get("source", "unknown"),
                "chunk_index": idx,
                "embedding": chunk.metadata.get("embedding")
            }
        }
        out_path = os.path.join(output_dir, f"chunk_{idx}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(chunk_data, f, indent=2, ensure_ascii=False)


# -------------------------
# Chroma Embeddings
# -------------------------
def embed_to_chromadb(documents):
    chunks = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP).split_documents(documents)
    print("Embedding documents into ChromaDB...")
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")
    vectordb = Chroma(
        collection_name=CHROMA_COLLECTION,
        embedding_function=embeddings_model,
        persist_directory=CHROMA_DIR
    )
    vectordb.add_documents(chunks)


# -------------------------
# Generate embeddings
# -------------------------
def generate_embeddings(chunks):
    print("Generating embeddings for chunks...")
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")
    for chunk in tqdm(chunks, desc="Generating embeddings"):
        chunk.metadata['embedding'] = embeddings_model.embed_documents([chunk.page_content])[0]
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
# Async extraction with progress
# -------------------------
async def extract_all_entities_relations(chunks):
    results = []
    pbar = tqdm_asyncio(total=len(chunks), desc="Extracting entities/relations")
    
    async def worker(chunk):
        entities, relations = await extract_entities_relations_async(chunk.page_content)
        pbar.update(1)
        return entities, relations

    tasks = [worker(chunk) for chunk in chunks]

    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
    
    pbar.close()
    return results


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
async def create_similarity_edges(chunks, threshold=SIMILARITY_THRESHOLD):
    embeddings = [chunk.metadata['embedding'] for chunk in chunks]
    similarity_matrix = cosine_similarity(embeddings)
    async with driver.session() as session:
        for i in range(len(embeddings)):
            for j in range(i+1, len(embeddings)):
                if similarity_matrix[i][j] > threshold:
                    await session.run(
                        "MATCH (c1:Chunk {id:$i}), (c2:Chunk {id:$j}) "
                        "MERGE (c1)-[:SIMILAR_TO {score:$score}]->(c2)",
                        i=i, j=j, score=float(similarity_matrix[i][j])
                    )


# -------------------------
# Main pipeline
# -------------------------
def main_pipeline():
    documents = load_pdfs(DATA_DIR)

    # Save original documents as JSON
    # save_documents_as_json(documents, output_dir=JSON_DIR)

    # Embed original documents to ChromaDB
    # embed_to_chromadb(documents)

    # Split into chunks
    chunked_docs = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    ).split_documents(documents)
    
    # Generate embeddings
    chunked_docs = generate_embeddings(chunked_docs)

    # Extract entities and relations asynchronously
    print("Extracting entities and relations...")
    extraction_results = asyncio.run(extract_all_entities_relations(chunked_docs))

    chunks_with_entities = [
        (chunk.page_content, entities, relations)
        for chunk, (entities, relations) in zip(chunked_docs, extraction_results)
    ]

    # Ingest into Neo4j
    print("Ingesting chunks into Neo4j...")
    asyncio.run(ingest_chunks_async(chunks_with_entities))

    # Create similarity edges
    print("Creating similarity edges...")
    asyncio.run(create_similarity_edges(chunked_docs))

    print("Pipeline complete. JSON + ChromaDB + Neo4j ready.")


# -------------------------
# Run pipeline
# -------------------------
if __name__ == "__main__":
    main_pipeline()
