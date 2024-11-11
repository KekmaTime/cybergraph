import os
from typing import Dict, List, Any
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from ..graph.graph_builder import GraphBuilder
import networkx as nx

# Define prompt template for query analysis
QUERY_ANALYSIS_TEMPLATE = """
You are a cybersecurity expert analyzing a security scan graph. Based on the following context and query, provide a detailed analysis.

Context Information:
{context}

User Query: {query}

Analyze the information and provide a clear, security-focused response. Include specific details about hosts, ports, services, and vulnerabilities where relevant.
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
            model="gpt-4",
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