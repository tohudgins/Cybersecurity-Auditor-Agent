import os
import json
from dotenv import load_dotenv
from typing import Callable, List, Optional

# LangChain / model imports (provider packages used in your original file)
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Text splitting / docs (used elsewhere if needed)
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

# Optional Neo4j driver
try:
    from neo4j import GraphDatabase
    _HAS_NEO4J = True
except Exception:
    _HAS_NEO4J = False

load_dotenv()

# --- Configuration ---
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# --- Utilities ---
def format_docs_text(docs: List[Document]) -> str:
    return "\n\n".join(d.page_content for d in docs)

# --- Tool 1: Vector Query Tool (RAG) ---
def create_vector_rag_tool() -> Callable[[str], str]:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings,
        collection_name=CHROMA_COLLECTION,
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

    prompt_tmpl = PromptTemplate(
        input_variables=["context", "question"],
        template=(
            "You are a cybersecurity compliance assistant. Answer only from the context below.\n\n"
            "Context:\n{context}\n\nQuestion:\n{question}\n\nIf the answer is not in the context, respond: "
            "\"I don't know based on the provided materials.\""
        ),
    )
    chain = LLMChain(llm=llm, prompt=prompt_tmpl)

    def vector_tool(question: str) -> str:
        docs = retriever.get_relevant_documents(question)
        context = format_docs_text(docs)
        return chain.run({"context": context, "question": question})

    return vector_tool

# --- Tool 2: Summarization Tool ---
def create_summary_tool() -> Callable[[str], str]:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings,
        collection_name=CHROMA_COLLECTION,
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 15})

    prompt_tmpl = PromptTemplate(
        input_variables=["context", "topic"],
        template=(
            "You are an expert summarizer for cybersecurity frameworks.\n\n"
            "Given the context below, produce a concise, structured summary focused on: {topic}\n\n"
            "Context:\n{context}\n\nSummary:"
        ),
    )
    chain = LLMChain(llm=llm, prompt=prompt_tmpl)

    def summary_tool(topic: str) -> str:
        docs = retriever.get_relevant_documents(topic)
        context = format_docs_text(docs)
        return chain.run({"context": context, "topic": topic})

    return summary_tool

# --- Tool 3: Knowledge Graph / Cypher Tool ---
def create_kg_query_tool() -> Callable[[str], str]:
    cypher_llm = ChatOpenAI(model="gpt-4o", temperature=0)

    prompt_tmpl = PromptTemplate(
        input_variables=["question"],
        template=(
            "Translate the following natural language question into a single Cypher query.\n"
            "Only output the Cypher query, without any explanatory text.\n\nQuestion:\n{question}\n\nCypher:"
        ),
    )
    chain = LLMChain(llm=cypher_llm, prompt=prompt_tmpl)

    def kg_tool(question: str) -> str:
        cypher = chain.run({"question": question}).strip()
        # crude cleanup: extract last code-like line if LLM added commentary
        lines = [l.strip() for l in cypher.splitlines() if l.strip()]
        if lines:
            cypher = lines[-1]

        result_payload = {"cypher": cypher}

        if _HAS_NEO4J and NEO4J_PASSWORD:
            try:
                driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
                with driver.session() as session:
                    records = list(session.run(cypher))
                    # convert records to serializable form
                    results = [r.data() for r in records]
                result_payload["results"] = results
            except Exception as e:
                result_payload["error"] = str(e)
        else:
            result_payload["note"] = "Neo4j driver not available or credentials not provided; cypher returned only."

        return json.dumps(result_payload, indent=2, ensure_ascii=False)

    return kg_tool

# --- Example usage when run directly ---
if __name__ == "__main__":
    print("Loading tools (using existing Chroma DB and Neo4j if configured)...")
    vector_tool = create_vector_rag_tool()
    summary_tool = create_summary_tool()
    kg_tool = create_kg_query_tool()

    q1 = "What is the primary purpose of the NIST Cybersecurity Framework?"
    try:
        print("Vector RAG answer:\n", vector_tool(q1))
    except Exception as e:
        print("Vector tool error:", e)

    q2 = "Types of security controls across frameworks"
    try:
        print("Summary:\n", summary_tool(q2))
    except Exception as e:
        print("Summary tool error:", e)

    q3 = "Find nodes relating NIST controls to ISO 27001 controls"
    try:
        print("KG tool output:\n", kg_tool(q3))
    except Exception as e:
        print("KG tool error:", e)