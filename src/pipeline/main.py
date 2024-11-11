from sre_parse import State
from typing import Dict, Union, List, Any
from langgraph.graph import Graph, StateGraph
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
import json

from ..processors.text_processor import process_text
from ..processors.vision_processor import process_image
from ..graph.graph_builder import GraphBuilder

def create_pipeline():
    # Initialize components
    graph_builder = GraphBuilder()
    
    # Define state type
    class State(dict):
        """The state of our graph execution"""
        def __init__(self):
            super().__init__()
            self.update({
                "input_data": None,
                "extracted_info": None,
                "graph_updates": None,
                "errors": []
            })
    
    # Create workflow graph
    workflow = StateGraph(State)
    
    # Define processing nodes
    def process_input(state: State) -> State:
        try:
            input_data = state["input_data"]
            if isinstance(input_data, str):
                # Process text input
                extracted_info = process_text(input_data)
            elif isinstance(input_data, dict) and "image_path" in input_data:
                # Process image input with context if available
                context = input_data.get("context", "")
                extracted_info = process_image(input_data["image_path"], context)
            else:
                raise ValueError("Invalid input format")
            
            state["extracted_info"] = extracted_info
        except Exception as e:
            state["errors"].append(str(e))
        return state

    def update_graph(state: State) -> State:
        try:
            if state["extracted_info"]:
                # Update graph with extracted information
                graph_builder.add_or_update_host(state["extracted_info"])
                state["graph_updates"] = {
                    "status": "success",
                    "updates": state["extracted_info"]
                }
        except Exception as e:
            state["errors"].append(str(e))
        return state

    def validate_results(state: State) -> str:
        if state["errors"]:
            return "error"
        return "success"

    # Add nodes to workflow
    workflow.add_node("process_input", process_input)
    workflow.add_node("update_graph", update_graph)

    # Add edges
    workflow.add_edge("process_input", "update_graph")
    
    # Set conditional edges based on validation
    workflow.add_conditional_edges(
        "update_graph",
        validate_results,
        {
            "success": None,  # End of workflow
            "error": None     # End of workflow
        }
    )

    # Set entry point
    workflow.set_entry_point("process_input")

    # Compile workflow
    return workflow.compile()

def run_pipeline(input_data: Union[str, Dict[str, str]]) -> Dict[str, Any]:
    """
    Run the security analysis pipeline
    
    Args:
        input_data: Either raw text or dict with image_path
    
    Returns:
        Dict containing processing results and any errors
    """
    workflow = create_pipeline()
    
    # Initialize state
    initial_state = State()
    initial_state["input_data"] = input_data
    
    # Execute workflow
    final_state = workflow.invoke(initial_state)
    
    return {
        "status": "error" if final_state["errors"] else "success",
        "errors": final_state["errors"],
        "updates": final_state["graph_updates"],
        "extracted_info": final_state["extracted_info"]
    }