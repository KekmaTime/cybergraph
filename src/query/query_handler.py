import os
from typing import Dict, List, Any, Tuple
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import (
    RunnableBranch,
    RunnableLambda,
    RunnableParallel,
    RunnablePassthrough
)
from langchain_core.pydantic_v1 import BaseModel, Field
from ..graph.graph_builder import GraphBuilder
import networkx as nx
from langchain.schema import HumanMessage, AIMessage
from datetime import datetime
import logging

# Entity extraction for security entities
class SecurityEntities(BaseModel):
    """Security-related entities found in text."""
    hosts: List[str] = Field(description="Hostnames and IP addresses")
    ports: List[str] = Field(description="Port numbers and services")
    vulnerabilities: List[str] = Field(description="Identified vulnerabilities")
    credentials: List[str] = Field(description="Any credentials or authentication info")

SECURITY_ENTITY_PROMPT = """
You are a cybersecurity expert analyzing security scan outputs. Extract key security entities from the text.
Focus on identifying:
- Hosts and IP addresses
- Open ports and services
- Vulnerabilities and exposures
- Credentials or authentication information

Text: {text}

Extract and categorize all security-relevant entities.
"""

SECURITY_ANALYSIS_TEMPLATE = """You are a cybersecurity expert analyzing security scan results and vulnerability data.
Based on the following context, answer the user's query with detailed technical analysis.

Graph Context (Hosts, Services, Vulnerabilities):
{graph_context}

Vector Search Results:
{vector_context}

User Query: {query}

Provide a clear, detailed response focusing on:
1. Relevant security findings
2. Technical details of vulnerabilities
3. Affected services and ports
4. Potential impact and risks
5. Relationships between identified components
"""

def extract_security_entities(text: str, llm: ChatOpenAI) -> SecurityEntities:
    """Extract security-relevant entities from text using LLM."""
    prompt = ChatPromptTemplate.from_template(SECURITY_ENTITY_PROMPT)
    chain = prompt | llm.with_structured_output(SecurityEntities)
    return chain.invoke({"text": text})

def prepare_graph_context(graph_data: Dict[str, Any], vector_results: Dict[str, Any]) -> str:
    """Prepare context from graph data and vector search results with better organization."""
    context_parts = []
    
    # Add vector search results first
    if vector_results and 'documents' in vector_results:
        context_parts.append("### Vector Search Results")
        context_parts.extend(vector_results['documents'])
    
    if graph_data:
        # Group by host
        hosts = {}
        for node, attr in graph_data.items():
            if attr.get('type') == 'host':
                hosts[node] = {
                    'services': [],
                    'vulnerabilities': [],
                    'credentials': [],
                    'details': attr
                }
        
        # Collect related entities
        for node, attr in graph_data.items():
            if attr.get('type') == 'service' and attr.get('host') in hosts:
                hosts[attr['host']]['services'].append({
                    'port': attr.get('port'),
                    'name': attr.get('name'),
                    'version': attr.get('version'),
                    'state': attr.get('state')
                })
            elif attr.get('type') == 'vulnerability' and attr.get('host') in hosts:
                hosts[attr['host']]['vulnerabilities'].append({
                    'name': attr.get('name'),
                    'severity': attr.get('severity'),
                    'description': attr.get('description')
                })
            elif attr.get('type') == 'credential' and attr.get('host') in hosts:
                hosts[attr['host']]['credentials'].append({
                    'service': attr.get('service'),
                    'username': attr.get('username'),
                    'type': attr.get('auth_type')
                })
        
        # Format output
        context_parts.append("\n### Host Information")
        for host, data in hosts.items():
            context_parts.append(f"\nHost: {host}")
            context_parts.append(f"OS: {data['details'].get('os', 'Unknown')}")
            
            if data['services']:
                context_parts.append("Services:")
                for svc in data['services']:
                    context_parts.append(f"- Port {svc['port']}: {svc['name']} "
                                      f"(Version: {svc.get('version', 'unknown')})")
            
            if data['vulnerabilities']:
                context_parts.append("Vulnerabilities:")
                for vuln in data['vulnerabilities']:
                    context_parts.append(f"- {vuln['name']} ({vuln['severity']} severity)")
                    
            if data['credentials']:
                context_parts.append("Authentication:")
                for cred in data['credentials']:
                    context_parts.append(f"- {cred['service']}: {cred['type']}")
    
    return "\n".join(context_parts)

def format_chat_history(chat_history: List[Tuple[str, str]]) -> List:
    """Format chat history into message format."""
    buffer = []
    for human, ai in chat_history:
        buffer.append(HumanMessage(content=human))
        buffer.append(AIMessage(content=ai))
    return buffer

CONDENSE_QUESTION_PROMPT = PromptTemplate.from_template(
    """Given the following conversation and a follow up question, rephrase the follow up question to be a standalone question,
    in its original language, focused on cybersecurity aspects.
    Chat History:
    {chat_history}
    Follow Up Input: {question}
    Standalone question:"""
)

def create_search_query_chain():
    """Create a chain for processing search queries with chat history."""
    return RunnableBranch(
        (
            RunnableLambda(lambda x: bool(x.get("chat_history"))),
            RunnablePassthrough.assign(
                chat_history=lambda x: format_chat_history(x["chat_history"])
            )
            | CONDENSE_QUESTION_PROMPT
            | ChatOpenAI(model="gpt-4-0125-preview", temperature=0)
            | StrOutputParser(),
        ),
        RunnableLambda(lambda x: x["question"]),
    )

def create_rag_chain(retriever):
    """Create the main RAG chain for security analysis."""
    search_query_chain = create_search_query_chain()
    
    return (
        RunnableParallel(
            {
                "context": search_query_chain | retriever,
                "question": RunnablePassthrough(),
            }
        )
        | ChatPromptTemplate.from_template(SECURITY_ANALYSIS_TEMPLATE)
        | ChatOpenAI(model="gpt-4-0125-preview", temperature=0)
        | StrOutputParser()
    )

def query_handler(query: str, graph_builder: GraphBuilder, chat_history: List[Tuple[str, str]] = None) -> Dict[str, Any]:
    """
    Handle security-related queries with graph traversal and RAG.
    
    Args:
        query: User's security question
        graph_builder: GraphBuilder instance
        chat_history: Optional chat history for context
    
    Returns:
        Dict containing analysis and relevant information
    """
    try:
        # Extract entities from query
        llm = ChatOpenAI(model="gpt-4-0125-preview", temperature=0)
        entities = extract_security_entities(query, llm)
        
        # Get relevant graph context and vector search results
        retriever = graph_builder.get_hybrid_retriever(entities)
        rag_chain = create_rag_chain(retriever)
        
        # Generate response
        response = rag_chain.invoke({
            "question": query,
            "chat_history": chat_history or []
        })
        
        return {
            "status": "success",
            "response": response,
            "entities": entities.dict(),
            "metadata": {
                "model": "gpt-4-0125-preview",
                "timestamp": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        logging.error(f"Error in query_handler: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "query": query
        }