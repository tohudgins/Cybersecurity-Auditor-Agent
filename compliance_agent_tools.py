import os
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain.chains import GraphCypherQAChain, load_summarize_chain
from langchain_community.graphs import Neo4jGraph

# Load environment variables from a .env file
load_dotenv()

# --- Configuration ---
CHROMA_DIR = ".chromadb/"
CHROMA_COLLECTION = "Cybersecurity_Frameworks"
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# --- Helper Function ---
def format_docs(docs):
    """A utility to combine document contents into a single string for context."""
    return "\n\n".join(doc.page_content for doc in docs)

# --- Tool 1: Vector Query Tool (for General Q&A) ---
def create_vector_rag_tool():
    """
    Builds and returns a Retrieval-Augmented Generation (RAG) chain.
    This tool is best for answering general, fact-based questions.
    """
    print("🛠️  Initializing Vector RAG Tool...")
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings_model,
        collection_name=CHROMA_COLLECTION
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

    template = """
    You are an expert assistant for cybersecurity and compliance questions.
    Answer the question based *only* on the following context.
    If the context does not contain the answer, state that you don't know.

    Context:
    {context}

    Question:
    {question}
    """
    prompt = ChatPromptTemplate.from_template(template)

    rag_chain = (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )
    return rag_chain

# --- Tool 2: Summarization Tool (for Topic Summaries) ---
def create_summary_tool():
    """
    Builds and returns a retrieve-then-summarize chain.
    This tool is best for broad questions that require summarizing a topic
    across multiple documents.
    """
    print("🛠️  Initializing Summarization Tool...")
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")

    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings_model,
        collection_name=CHROMA_COLLECTION
    )
    # Retrieve more documents for a comprehensive summary
    retriever = vectorstore.as_retriever(search_kwargs={"k": 15})

    # The "stuff" chain is simple and effective for summarization
    summarize_chain = load_summarize_chain(llm, chain_type="stuff")
    
    # This chain retrieves documents and then passes them to the summarizer
    return retriever | summarize_chain

# --- Tool 3: Knowledge Graph Tool (for Comparisons) ---
def create_kg_query_tool():
    """
    Builds and returns a Text-to-Cypher chain for the knowledge graph.
    This tool is best for compare-and-contrast or multi-hop questions.
    """
    print("🛠️  Initializing Knowledge Graph Tool...")
    
    graph = Neo4jGraph(
        url=NEO4J_URI,
        username=NEO4J_USER,
        password=NEO4J_PASSWORD
    )
    
    # Use a powerful model for generating accurate Cypher queries
    cypher_llm = ChatOpenAI(model="gpt-4o", temperature=0)
    # Use a general model for formatting the final answer
    qa_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    
    kg_chain = GraphCypherQAChain.from_llm(
        cypher_llm=cypher_llm,
        qa_llm=qa_llm,
        graph=graph,
        verbose=True # Set to True to see the generated Cypher query in action
    )
    return kg_chain

if __name__ == '__main__':
    # --- Example Usage ---
    # This block demonstrates how to initialize and test each tool.
    
    print("--- Testing Tool 1: Vector RAG Tool ---")
    vector_tool = create_vector_rag_tool()
    question1 = "What is the primary purpose of the NIST Cybersecurity Framework?"
    response1 = vector_tool.invoke(question1)
    print(f"Question: {question1}\nAnswer: {response1}\n")

    print("--- Testing Tool 2: Summarization Tool ---")
    summary_tool = create_summary_tool()
    question2 = "Summarize the different types of security controls mentioned across the frameworks."
    response2 = summary_tool.invoke(question2)
    print(f"Question: {question2}\nSummary: {response2['output_text']}\n")

    print("--- Testing Tool 3: Knowledge Graph Tool ---")
    kg_tool = create_kg_query_tool()
    question3 = "Compare the controls mandated by NIST with those from ISO 27001."
    response3 = kg_tool.invoke(question3)
    print(f"Question: {question3}\nAnswer: {response3['result']}\n")

