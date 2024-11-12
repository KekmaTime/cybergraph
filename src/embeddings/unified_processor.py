from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions
import json
import os
from dotenv import load_dotenv
from typing import Dict, List
from ..processors.security_image_processor import SecurityImageProcessor
from ..graph.graph_builder import GraphBuilder

load_dotenv()

def create_chroma_collection():
    """Create or get the Chroma collection with OpenAI embeddings"""
    client = chromadb.PersistentClient(path="data/chroma")
    
    embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.getenv("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    
    try:
        collection = client.get_or_create_collection(
            name="security_content",
            embedding_function=embedding_fn,
            metadata={"hnsw:space": "cosine"}
        )
        return collection
    except Exception as e:
        print(f"Error creating collection: {e}")
        raise

async def process_all_content():
    """Process all content using the SecurityImageProcessor"""
    collection = create_chroma_collection()
    graph_builder = GraphBuilder()
    image_processor = SecurityImageProcessor(graph_builder)
    
    # Process markdown files
    markdown_dir = Path("data/raw/writeups")
    if markdown_dir.exists():
        for md_file in markdown_dir.glob("*.MD"):
            # Process markdown content
            processed = await image_processor.process_markdown_content(md_file)
            if processed:
                collection.add(
                    documents=[processed["content"]],
                    metadatas=[processed["metadata"]],
                    ids=[f"md_{hash(processed['content'])}"[:64]]
                )
                print(f"Processed markdown: {md_file.name}")
                
                # Process images in markdown
                await image_processor.process_markdown_images(md_file)
    
    # Process standalone images
    images_dir = Path("data/raw/images")
    if images_dir.exists():
        for image_path in images_dir.glob("*.{jpg,jpeg,png}"):
            image_id = await image_processor.process_and_store_image(str(image_path))
            if image_id:
                print(f"Processed standalone image: {image_path.name}")
    # Process images using GPT-4-Vision
    metadata_file = Path("data/processed/images/metadata.jsonl")
    if metadata_file.exists():
        with open(metadata_file) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    embedding = await image_processor.create_image_embedding(
                        entry["local_path"],
                        entry.get("context", "")
                    )
                    if embedding:
                        collection.add(
                            documents=[embedding["description"]],
                            metadatas=[{
                                "source": entry["source_file"],
                                "image_path": entry["local_path"],
                                "title": entry["title"],
                                "type": "image",
                                "url": entry.get("url", "")
                            }],
                            ids=[f"img_{hash(embedding['description'])}"[:64]]
                        )
                        print(f"Processed image: {entry['local_path']}")

def query_content(query: str, n_results: int = 5):
    collection = create_chroma_collection()
    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        include=["documents", "metadatas"]
    )
    return results

if __name__ == "__main__":
    process_all_content()