import os
import json
import asyncio
import logging
from pypdf import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from neo4j import AsyncGraphDatabase
from dotenv import load_dotenv
from openai import AsyncOpenAI
from tqdm import tqdm
from tqdm.asyncio import tqdm_asyncio
from tenacity import retry, stop_after_attempt, wait_random_exponential

load_dotenv()

# -------------------------
# Configuration & Setup
# -------------------------
# --- Directories and Constants ---
DATA_DIR = "data"
JSON_DIR = "json_docs"
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"

# --- NEW: Chunking Configurations ---
# For retrieval tasks (ChromaDB, JSON) where smaller, focused chunks are better
RETRIEVAL_CHUNK_SIZE = 1000
RETRIEVAL_CHUNK_OVERLAP = 100

# For knowledge graph extraction where more context is helpful
KG_CHUNK_SIZE = 2000
KG_CHUNK_OVERLAP = 200

CONCURRENCY_LIMIT = 15

# --- API and Database Credentials ---
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    filename='pipeline.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Global Clients & Controls ---
client = AsyncOpenAI(api_key=OPENAI_API_KEY)
driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

# -------------------------
# 1. PDF Loading
# -------------------------
def load_pdfs(directory_path):
    """Loads all PDFs and extracts text into Document objects."""
    pdf_files = [f for f in os.listdir(directory_path) if f.endswith(".pdf")]
    documents = []
    print("Loading and extracting text from PDFs...")
    for pdf_file in pdf_files:
        try:
            reader = PdfReader(os.path.join(directory_path, pdf_file))
            text = "".join([page.extract_text() or "" for page in reader.pages])
            if text:
                documents.append(Document(page_content=text, metadata={"source": pdf_file}))
        except Exception as e:
            logging.error(f"Error reading {pdf_file}: {e}")
    return documents

# -------------------------
# 2a. Save Chunks as JSON
# -------------------------
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

# -------------------------
# 2b. Embed Chunks into ChromaDB
# -------------------------
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
    vectordb.persist()
    print("ChromaDB persistence complete.")


# -------------------------
# 3. Entity & Relation Extraction
# -------------------------
@retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(3))
async def extract_entities_relations_async(chunk_text, chunk_id):
    async with sem:
        prompt = f"""
        Extract cybersecurity-specific entities and relations from the following text.
        Return a valid JSON object with "entities" and "relations" keys.
        Entities should be a list of objects, e.g., [{{"text": "...", "label": "..."}}]
        Relations should be a list of objects, e.g., [{{"source": "...", "target": "...", "type": "..."}}]
        Text:
        {chunk_text}
        """
        try:
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity knowledge graph builder. Respond with JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            entities, relations = [], []
            raw_entities = result.get("entities", [])
            if isinstance(raw_entities, list):
                for e in raw_entities:
                    if isinstance(e, dict) and "text" in e and "label" in e:
                        entities.append((e["text"], e["label"]))
                    else:
                        logging.warning(f"Malformed entity in chunk {chunk_id}: {e}")
            raw_relations = result.get("relations", [])
            if isinstance(raw_relations, list):
                relations = raw_relations
            return entities, relations
        except Exception as e:
            logging.error(f"Error processing chunk {chunk_id}: {e}")
            return [], []

async def extract_all_entities_relations(chunks):
    tasks = [extract_entities_relations_async(chunk.page_content, i) for i, chunk in enumerate(chunks)]
    print("Extracting entities and relations from knowledge graph-sized chunks...")
    results = await tqdm_asyncio.gather(*tasks)
    return results

# -------------------------
# 4. Neo4j Ingestion
# -------------------------
async def store_in_neo4j(session, chunk_id, chunk_text, entities, relations):
    await session.run("MERGE (c:Chunk {id:$id}) SET c.text=$text", id=chunk_id, text=chunk_text)
    for entity, label in entities:
        await session.run("MERGE (e:Entity {name: $name}) ON CREATE SET e.label = $label", name=entity, label=label)
        await session.run("MATCH (c:Chunk {id:$chunk_id}), (e:Entity {name:$name}) MERGE (c)-[:MENTIONS]->(e)", chunk_id=chunk_id, name=entity)
    for rel in relations:
        if isinstance(rel, dict) and all(k in rel for k in ["source", "target", "type"]):
            rel_type = ''.join(e for e in rel['type'] if e.isalnum()).upper()
            if not rel_type: continue
            await session.run(f"MATCH (e1:Entity {{name: $src}}), (e2:Entity {{name: $tgt}}) MERGE (e1)-[:{rel_type}]->(e2)", src=rel["source"], tgt=rel["target"])

async def ingest_into_neo4j(chunks, extraction_results):
    print("Ingesting knowledge graph data into Neo4j...")
    async with driver.session() as session:
        tasks = [store_in_neo4j(session, i, chunk.page_content, entities, relations) for i, (chunk, (entities, relations)) in enumerate(zip(chunks, extraction_results))]
        await asyncio.gather(*tasks)

# -------------------------
# Main Pipeline Orchestration
# -------------------------
async def main():
    """Runs the entire pipeline with dual chunking strategies."""
    try:
        documents = load_pdfs(DATA_DIR)

        # --- Strategy 1: Smaller chunks for JSON and ChromaDB ---
        retrieval_splitter = RecursiveCharacterTextSplitter(
            chunk_size=RETRIEVAL_CHUNK_SIZE, chunk_overlap=RETRIEVAL_CHUNK_OVERLAP
        )
        chunks_for_retrieval = retrieval_splitter.split_documents(documents)
        print(f"Created {len(chunks_for_retrieval)} chunks for retrieval/JSON.")
        save_chunks_as_json(chunks_for_retrieval)
        embed_to_chromadb(chunks_for_retrieval)

        # --- Strategy 2: Larger chunks for Knowledge Graph ---
        kg_splitter = RecursiveCharacterTextSplitter(
            chunk_size=KG_CHUNK_SIZE, chunk_overlap=KG_CHUNK_OVERLAP
        )
        chunks_for_kg = kg_splitter.split_documents(documents)
        print(f"Created {len(chunks_for_kg)} chunks for the knowledge graph.")
        
        # Asynchronous processing for the knowledge graph
        extraction_results = await extract_all_entities_relations(chunks_for_kg)
        await ingest_into_neo4j(chunks_for_kg, extraction_results)
        
        print("\n✅ Pipeline complete. All data stores are ready.")

    except Exception as e:
        logging.critical(f"A critical error occurred in the main pipeline: {e}")
        print(f"❌ A critical error occurred. Check pipeline.log for details.")
    finally:
        await driver.close()

# -------------------------
# Run the pipeline
# -------------------------
if __name__ == "__main__":
    asyncio.run(main())