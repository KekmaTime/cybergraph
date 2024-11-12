from typing import Dict, List, Any, Optional
from langchain_community.graphs import Neo4jGraph
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain.schema import Document
from langchain.text_splitter import TokenTextSplitter
from langchain_core.pydantic_v1 import BaseModel
import logging
from datetime import datetime

class GraphBuilder:
    """Handles graph database and vector store operations for security data."""
    
    def __init__(self, 
                 neo4j_url: str,
                 neo4j_user: str,
                 neo4j_password: str,
                 chroma_persist_dir: str):
        """Initialize graph and vector store connections."""
        try:
            # Initialize Neo4j
            self.graph = Neo4jGraph(
                url=neo4j_url,
                username=neo4j_user,
                password=neo4j_password
            )
            
            # Initialize Chroma with OpenAI embeddings
            self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
            self.vector_store = Chroma(
                persist_directory=chroma_persist_dir,
                embedding_function=self.embeddings
            )
            
            # Initialize text splitter for document processing
            self.text_splitter = TokenTextSplitter(
                chunk_size=512,
                chunk_overlap=50
            )
            
            self._init_schema()
            
        except Exception as e:
            logging.error(f"Failed to initialize GraphBuilder: {str(e)}", exc_info=True)
            raise

    def _init_schema(self):
        """Initialize Neo4j schema for security entities."""
        constraints = """
        CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE;
        CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE;
        CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE;
        CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
        """
        self.graph.query(constraints)

    def add_security_data(self, data: Dict[str, Any], source: str):
        """
        Add security scan data to both graph and vector store.
        
        Args:
            data: Dictionary containing security scan results
            source: Source identifier (e.g., 'nmap_scan', 'vulnerability_scan')
        """
        try:
            # Process text for vector store
            documents = self._prepare_documents(data, source)
            self.vector_store.add_documents(documents)
            
            # Create graph nodes and relationships
            self._create_graph_entities(data, source)
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "source": source,
                "doc_count": len(documents)
            }
            
        except Exception as e:
            logging.error(f"Error adding security data: {str(e)}", exc_info=True)
            raise

    def _prepare_documents(self, data: Dict[str, Any], source: str) -> List[Document]:
        """Prepare documents for vector store."""
        # Convert scan data to text format
        text = self._convert_scan_to_text(data)
        
        # Split into chunks
        texts = self.text_splitter.split_text(text)
        
        # Create documents with metadata
        return [
            Document(
                page_content=chunk,
                metadata={
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                    "type": "security_scan"
                }
            ) for chunk in texts
        ]

    def _create_graph_entities(self, data: Dict[str, Any], source: str):
        """Create nodes and relationships in Neo4j."""
        # Create host node
        host_query = """
        MERGE (h:Host {id: $host_id})
        SET h.ip = $ip,
            h.hostname = $hostname,
            h.last_seen = $timestamp,
            h.source = $source
        """
        
        # Create port and service nodes
        port_query = """
        MATCH (h:Host {id: $host_id})
        MERGE (p:Port {id: $port_id})
        SET p.number = $port_num,
            p.state = $state,
            p.last_seen = $timestamp
        MERGE (s:Service {id: $service_id})
        SET s.name = $service_name,
            s.version = $version
        MERGE (h)-[:HAS_PORT]->(p)
        MERGE (p)-[:RUNS_SERVICE]->(s)
        """
        
        # Execute queries with parameters
        self.graph.query(host_query, {
            "host_id": data["host"]["id"],
            "ip": data["host"]["ip"],
            "hostname": data["host"].get("hostname"),
            "timestamp": datetime.now().isoformat(),
            "source": source
        })
        
        for port in data.get("ports", []):
            self.graph.query(port_query, {
                "host_id": data["host"]["id"],
                "port_id": f"{data['host']['id']}:{port['number']}",
                "port_num": port["number"],
                "state": port["state"],
                "service_id": f"{data['host']['id']}:{port['number']}:{port['service']}",
                "service_name": port["service"],
                "version": port.get("version"),
                "timestamp": datetime.now().isoformat()
            })

    def get_hybrid_retriever(self, entities: BaseModel):
        """Get hybrid retriever combining graph and vector search."""
        return {
            "vector_results": self.vector_store.similarity_search(
                str(entities),
                k=3
            ),
            "graph_data": self._get_relevant_subgraph(entities)
        }

    def _get_relevant_subgraph(self, entities: BaseModel) -> Dict[str, Any]:
        """Get relevant subgraph based on entities."""
        # Build Cypher query based on entities
        query = """
        MATCH path = (h:Host)-[*1..3]-(related)
        WHERE h.ip IN $hosts OR h.hostname IN $hosts
        RETURN path
        """
        
        results = self.graph.query(query, {
            "hosts": entities.hosts
        })
        
        return self._process_graph_results(results)

    def _process_graph_results(self, results: List[Any]) -> Dict[str, Any]:
        """Process and format graph query results."""
        processed = {}
        for result in results:
            # Extract nodes and relationships from path
            # Format into dictionary structure
            # This is simplified - actual implementation would need more processing
            processed.update(result)
        return processed

    def _create_version_node(self, data: Dict[str, Any], source: str) -> str:
        """Create a version node to track changes."""
        version_query = """
        CREATE (v:Version {
            id: randomUUID(),
            timestamp: $timestamp,
            source: $source,
            changes: $changes
        })
        WITH v
        MATCH (h:Host {id: $host_id})
        CREATE (h)-[:HAS_VERSION]->(v)
        RETURN v.id as version_id
        """
        
        result = self.graph.query(
            version_query,
            {
                "timestamp": datetime.now().isoformat(),
                "source": source,
                "changes": data.get("changes", []),
                "host_id": data["host"]["id"]
            }
        )
        return result[0]["version_id"]

    def update_security_data(self, data: Dict[str, Any], source: str):
        """Enhanced update with version tracking and conflict resolution."""
        try:
            # Check for conflicts
            conflict_query = """
            MATCH (h:Host {id: $host_id})-[:HAS_VERSION]->(v:Version)
            WHERE v.timestamp > $last_check
            RETURN count(v) as updates
            """
            
            conflicts = self.graph.query(
                conflict_query,
                {
                    "host_id": data["host"]["id"],
                    "last_check": data.get("last_check", datetime.min.isoformat())
                }
            )
            
            if conflicts[0]["updates"] > 0:
                # Handle conflict by merging changes
                data = self._resolve_conflicts(data)
            
            # Create version node
            version_id = self._create_version_node(data, source)
            
            # Update graph with merge operations
            merge_query = """
            MATCH (h:Host {id: $host_id})
            SET h += $host_props
            WITH h
            UNWIND $ports as port
            MERGE (p:Port {id: $host_id + ':' + toString(port.number)})
            ON CREATE SET p = port.properties
            ON MATCH SET p += port.properties
            MERGE (h)-[:HAS_PORT]->(p)
            WITH p, port
            MERGE (s:Service {id: $host_id + ':' + toString(port.number) + ':' + port.service})
            ON CREATE SET s = port.service_props
            ON MATCH SET s += port.service_props
            MERGE (p)-[:RUNS_SERVICE]->(s)
            """
            
            # Execute update
            self.graph.query(merge_query, self._prepare_update_params(data))
            
            return {
                "status": "success",
                "version_id": version_id,
                "timestamp": datetime.now().isoformat(),
                "conflicts_resolved": conflicts[0]["updates"] > 0
            }
            
        except Exception as e:
            logging.error(f"Error in update_security_data: {str(e)}", exc_info=True)
            raise

    def _resolve_conflicts(self, new_data: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve conflicts between existing and new data."""
        query = """
        MATCH (h:Host {id: $host_id})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
        RETURN h, collect({port: p, service: s}) as services
        """
        
        existing = self.graph.query(query, {"host_id": new_data["host"]["id"]})
        merged = self._merge_data(existing[0], new_data)
        return merged

    def _process_graph_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced graph results processing with relationship handling."""
        processed = {}
        
        for result in results:
            # Process nodes
            for node in result.get("nodes", []):
                node_id = node["id"]
                if node_id not in processed:
                    processed[node_id] = {
                        "type": list(node["labels"])[0].lower(),
                        "properties": node["properties"],
                        "relationships": []
                    }
            
            # Process relationships
            for rel in result.get("relationships", []):
                start_node = rel["start"]
                end_node = rel["end"]
                rel_type = rel["type"]
                
                if start_node in processed:
                    processed[start_node]["relationships"].append({
                        "type": rel_type,
                        "target": end_node,
                        "properties": rel["properties"]
                    })
        
        return processed

    def _update_vector_documents(self, existing_doc: Document, new_docs: List[Document]):
        """Update vector store documents if content has changed."""
        if existing_doc.page_content != new_docs[0].page_content:
            self.vector_store.delete([existing_doc.metadata["id"]])
            self.vector_store.add_documents(new_docs)