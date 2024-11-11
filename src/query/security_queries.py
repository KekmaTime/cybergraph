from typing import Dict, List, Any

from query import query_handler
from ..graph.graph_builder import GraphBuilder

def get_common_queries() -> Dict[str, str]:
    """Return a dictionary of common security query templates"""
    return {
        "ports": "What ports are running on {host}?",
        "services": "What services are running on {host}?",
        "vulnerabilities": "What vulnerabilities are present on {host}?",
        "common_services": "What common services are running between {host1} and {host2}?",
        "login_forms": "Are there any login forms on {host}? Were any credentials captured?"
    }

def analyze_host_services(graph_builder: GraphBuilder, host: str) -> Dict[str, Any]:
    """Analyze services running on a specific host"""
    query = f"What services and ports are running on {host}?"
    return query_handler(query, graph_builder)

def compare_hosts(graph_builder: GraphBuilder, host1: str, host2: str) -> Dict[str, Any]:
    """Compare services and vulnerabilities between two hosts"""
    query = f"Compare the services and vulnerabilities between {host1} and {host2}"
    return query_handler(query, graph_builder)

def find_vulnerabilities(graph_builder: GraphBuilder, host: str) -> Dict[str, Any]:
    """Find vulnerabilities for a specific host"""
    query = f"What vulnerabilities were discovered on {host}?"
    return query_handler(query, graph_builder)