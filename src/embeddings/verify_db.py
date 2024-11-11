from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions
import os
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

def verify_chroma_collection():
    """Verify ChromaDB collection contents"""
    client = chromadb.PersistentClient(path="data/chroma")
    
    embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.getenv("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    
    try:
        collection = client.get_collection(
            name="security_images",
            embedding_function=embedding_fn
        )
        
        # Get all items
        results = collection.get()
        
        console = Console()
        table = Table(title="ChromaDB Collection Contents")
        table.add_column("Source")
        table.add_column("Title")
        table.add_column("Description Preview")
        
        for doc, metadata in zip(results['documents'], results['metadatas']):
            table.add_row(
                metadata['source'],
                metadata['title'],
                doc[0][:100] + "..." if doc[0] else "No description"
            )
        
        console.print(table)
        print(f"\nTotal items in collection: {len(results['documents'])}")
        
    except ValueError:
        print("Collection 'security_images' not found. Run the embedder first.")

if __name__ == "__main__":
    verify_chroma_collection()