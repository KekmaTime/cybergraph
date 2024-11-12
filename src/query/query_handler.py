import os
from typing import Dict, List, Any
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from ..graph.graph_builder import GraphBuilder
import networkx as nx
from ..embeddings.unified_processor import query_content

# Define prompt template for query analysis
QUERY_ANALYSIS_TEMPLATE = """
You are a cybersecurity expert analyzing a security scan graph. Based on the following context and query, provide a detailed analysis.

Context Information:
{context}

User Query: {query}

Analyze the information and provide a clear, security-focused response. Include specific details about hosts, ports, services, and vulnerabilities where relevant.
"""

SECURITY_ANALYSIS_TEMPLATE = """You are a cybersecurity expert analyzing security scan results and vulnerability data. 
Based on the following context, answer the user's query with detailed technical analysis.

Context from security scans and reports:
{context}

User Query: {query}

Provide a clear, detailed response focusing on:
1. Relevant security findings
2. Technical details of vulnerabilities
3. Affected services and ports
4. Potential impact and risks
"""

def prepare_graph_context(graph_data: Dict[str, Any], vector_results: Dict[str, Any]) -> str:
    """Prepare context from graph data and vector search results"""
    context_parts = []
    
    # Add vector search results
    if vector_results and 'documents' in vector_results:
        context_parts.extend(vector_results['documents'][0])
    
    # Add relevant graph information
    if graph_data:
        hosts = [node for node, attr in graph_data.items() if attr.get('type') == 'host']
        services = [node for node, attr in graph_data.items() if attr.get('type') == 'service']
        
        if hosts:
            context_parts.append("Hosts found:")
            for host in hosts:
                host_data = graph_data[host]
                context_parts.append(f"- {host}: {host_data}")
        
        if services:
            context_parts.append("\nServices detected:")
            for service in services:
                service_data = graph_data[service]
                context_parts.append(f"- {service}: Port {service_data.get('port')}, Service: {service_data.get('name')}")
    
    return "\n".join(context_parts)

def query_handler(query: str, graph_builder: GraphBuilder) -> Dict[str, Any]:
    """
    Handle security-related queries about the graph data
    
    Args:
        query: User's security-related question
        graph_builder: Instance of GraphBuilder containing the security graph
    
    Returns:
        Dict containing the analysis and relevant information
    """
    try:
        # Get relevant information from graph
        graph_results = graph_builder.query_graph(query)
        
        # Prepare context from graph data
        context = prepare_graph_context(
            graph_results['graph_data'],
            graph_results['vector_results']
        )
        
        # Initialize LLM
        llm = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0,
            api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Create and run prompt
        prompt = PromptTemplate(
            template=QUERY_ANALYSIS_TEMPLATE,
            input_variables=["context", "query"]
        )
        
        chain = prompt | llm
        
        # Generate response
        response = chain.invoke({
            "context": context,
            "query": query
        })
        
        return {
            "status": "success",
            "analysis": response.content,
            "context_used": context,
            "graph_data": graph_results
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "query": query
        }

def analyze_security_query(query: str) -> Dict[str, Any]:
    """Analyze a security query using ChromaDB and ChatGPT"""
    try:
        # Get relevant documents from ChromaDB
        results = query_content(query, n_results=3)
        
        # Prepare context from results
        context_parts = []
        for doc, metadata in zip(results['documents'][0], results['metadatas'][0]):
            context_parts.append(f"Source: {metadata['source']} ({metadata['type']})")
            context_parts.append(doc)
            context_parts.append("-" * 40)
        
        context = "\n".join(context_parts)
        
        # Initialize ChatGPT
        llm = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0,
            api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Create prompt
        prompt = PromptTemplate(
            template=SECURITY_ANALYSIS_TEMPLATE,
            input_variables=["context", "query"]
        )
        
        # Generate response
        chain = prompt | llm
        response = chain.invoke({
            "context": context,
            "query": query
        })
        
        return {
            "status": "success",
            "response": response.content
        }
        
    except Exception as e:
        return {
            "status": "error",
            "response": f"Error processing query: {str(e)}"
        }