import networkx as nx
from typing import Dict, Any
import chromadb
from chromadb.config import Settings

class GraphBuilder:
    def __init__(self):
        self.graph = nx.Graph()
        self.chroma_client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory="db"
        ))
        self.collection = self.chroma_client.create_collection("security_data")
    
    def add_or_update_host(self, host_data: Dict[str, Any]):
        host_id = host_data.get("hostname", "unknown")
        
        if not self.graph.has_node(host_id):
            self.graph.add_node(host_id, type="host", **host_data)
            # Store in ChromaDB
            self.collection.add(
                documents=[str(host_data)],
                metadatas=[{"type": "host", "id": host_id}],
                ids=[host_id]
            )
        
        # Add ports and services
        for port, service in host_data.get("ports_services", {}).items():
            service_id = f"{host_id}_{port}_{service}"
            self.graph.add_node(service_id, type="service", port=port, name=service)
            self.graph.add_edge(host_id, service_id, relationship="runs")
    
    def query_graph(self, query: str) -> Dict:
        # Query ChromaDB for relevant context
        results = self.collection.query(
            query_texts=[query],
            n_results=3
        )
        
        # Get connected nodes from NetworkX
        # Implementation depends on specific query needs
        
        return {
            "vector_results": results,
            "graph_data": self.graph.nodes(data=True)
        }