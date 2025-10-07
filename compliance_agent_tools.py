import os
import json
from dotenv import load_dotenv
from typing import Callable, List, Optional

# LangChain / model imports
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.schema import Document
from langchain.chains.summarize import load_summarize_chain
from langchain.retrievers.multi_query import MultiQueryRetriever

# Optional Neo4j driver
try:
    from neo4j import GraphDatabase
    _HAS_NEO4J = True
except ImportError:
    _HAS_NEO4J = False

load_dotenv()

# --- Configuration ---
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# --- Neo4j Driver Singleton ---
NEO4J_DRIVER = None
if _HAS_NEO4J and NEO4J_URI and NEO4J_USER and NEO4J_PASSWORD:
    try:
        NEO4J_DRIVER = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        NEO4J_DRIVER.verify_connectivity()
        print("Neo4j connection successful.")
    except Exception as e:
        print(f"Warning: Could not connect to Neo4j. KG tool will only generate Cypher. Error: {e}")
        NEO4J_DRIVER = None

# --- Utilities ---
def format_docs_text(docs: List[Document]) -> str:
    return "\n\n".join(d.page_content for d in docs)

# --- Tool 1: Vector Query Tool (RAG with Enhanced Prompt) ---
def create_vector_rag_tool() -> Callable[[str], str]:
    # Using the flagship model for the best reasoning and synthesis
    llm = ChatOpenAI(model="gpt-5", temperature=0.2)
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings,
        collection_name=CHROMA_COLLECTION,
    )
    
    # Using the standard retriever with an increased number of documents for more context
    retriever = vectorstore.as_retriever(search_kwargs={"k": 10})

    # An explicit prompt requesting a detailed, multi-part answer
    prompt_tmpl = PromptTemplate(
        input_variables=["context", "question"],
        template=(
            "You are a cybersecurity compliance assistant. Your task is to answer the user's question based on the provided context.\n\n"
            "Provide a detailed, multi-paragraph answer that synthesizes the key information from the context and answers the question. "
            "Context:\n{context}\n\nQuestion:\n{question}\n\nDetailed Answer:"
        ),
    )
    
    chain = prompt_tmpl | llm | StrOutputParser()

    def vector_tool(question: str) -> str:
        docs = retriever.invoke(question)
        context = format_docs_text(docs)
        return chain.invoke({"context": context, "question": question})

    return vector_tool

# --- Tool 2: Thematic Summary Tool (ENHANCED WITH MULTI-QUERY) ---
def create_thematic_summary_tool() -> Callable[[str], str]:
    """
    Creates a high-level thematic summary tool that uses a multi-query
    retriever to gather a richer context.
    """
    # Use a capable model for generating queries and a fast one for summarizing
    query_llm = ChatOpenAI(model="gpt-5-mini", temperature=0.2)
    summary_llm = ChatOpenAI(model="gpt-5-nano", temperature=0.2) 
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings,
        collection_name=CHROMA_COLLECTION,
    )
    
    # Set up the multi-query retriever
    base_retriever = vectorstore.as_retriever(search_kwargs={"k": 10}) # Retrieve fewer docs per query
    multi_query_retriever = MultiQueryRetriever.from_llm(
        retriever=base_retriever, llm=query_llm
    )

    combine_prompt_template = """
    The following are key points extracted from several documents on the topic of "{topic}".
    Your task is to synthesize these points into a single, final, and coherent high-level summary.
    ---
    {text}
    ---
    Final, synthesized summary on the topic of "{topic}":
    """
    combine_prompt = PromptTemplate(template=combine_prompt_template, input_variables=["text", "topic"])

    summary_chain = load_summarize_chain(
        llm=summary_llm,
        chain_type="map_reduce",
        combine_prompt=combine_prompt,
    )

    def thematic_summary_tool(topic: str) -> str:
        print(f"Generating multiple queries for topic: '{topic}'...")
        # The multi-query retriever will fetch docs for all generated questions
        relevant_docs = multi_query_retriever.invoke(topic)
        
        if not relevant_docs:
            return "No relevant documents found for this topic."
            
        print(f"Found {len(relevant_docs)} documents across all queries. Starting summarization...")
        result = summary_chain.invoke({
            "input_documents": relevant_docs,
            "topic": topic
        })
        
        return result['output_text']

    return thematic_summary_tool

# --- Tool 3: Knowledge Graph / Cypher Tool ---
def get_graph_schema(driver) -> str:
    if not driver:
        return "Graph schema not available."
    try:
        with driver.session() as session:
            labels_query = "CALL db.labels() YIELD label RETURN collect(label) as labels"
            labels = session.run(labels_query).single()['labels']
            
            rels_query = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as rels"
            rels = session.run(rels_query).single()['rels']
            
            return f"Node Labels: {labels}\nRelationship Types: {rels}"
    except Exception as e:
        return f"Error fetching schema: {e}"


def create_kg_query_tool() -> Callable[[str], str]:
    # UPDATED to use the flagship gpt-5 model for complex Cypher generation
    cypher_llm = ChatOpenAI(model="gpt-5-mini", temperature=0)
    graph_schema = get_graph_schema(NEO4J_DRIVER)

    prompt_tmpl = PromptTemplate(
        input_variables=["question", "schema"],
        template=(
            "You are an expert Neo4j Cypher translator. Translate the following natural language question "
            "into a single, valid Cypher query based on the provided graph schema.\n\n"
            "Graph Schema:\n{schema}\n\n"
            "IMPORTANT: Only output the raw Cypher query itself, without any explanatory text, comments, or markdown code fences (```).\n\n"
            "Question:\n{question}\n\nCypher:"
        ),
    )
    
    chain = prompt_tmpl | cypher_llm | StrOutputParser()

    def kg_tool(question: str) -> str:
        cypher_raw = chain.invoke({"question": question, "schema": graph_schema})
        cypher = cypher_raw.strip().replace("```cypher", "").replace("```", "").strip()
        result_payload = {"cypher": cypher}

        if NEO4J_DRIVER:
            try:
                with NEO4J_DRIVER.session() as session:
                    records = list(session.run(cypher))
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
    print("\nLoading tools (using existing Chroma DB and Neo4j if configured)...")
    vector_tool = create_vector_rag_tool()
    summary_tool = create_thematic_summary_tool()
    kg_tool = create_kg_query_tool()
    print("Tools loaded.\n" + "="*50)

    q1 = "What is the primary purpose of the NIST Cybersecurity Framework?"
    print(f"\n[Query 1] Vector RAG Question:\n{q1}\n")
    try:
        print("Vector RAG answer:\n", vector_tool(q1))
    except Exception as e:
        print("Vector tool error:", e)
    print("="*50)

    q2 = "Types of security controls across frameworks"
    print(f"\n[Query 2] Filtered Summary Topic:\n{q2}\n")
    try:
        print("Filtered Summary:\n", summary_tool(q2))
    except Exception as e:
        print("Summary tool error:", e)
    print("="*50)

    q3 = "Find nodes relating NIST controls to ISO 27001 controls"
    print(f"\n[Query 3] KG Question:\n{q3}\n")
    try:
        print("KG tool output:\n", kg_tool(q3))
    except Exception as e:
        print("KG tool error:", e)
    print("="*50)
    
    # Close the driver connection when the application exits
    if NEO4J_DRIVER:
        NEO4J_DRIVER.close()