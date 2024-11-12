from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions
import json
import os
from dotenv import load_dotenv
from typing import Dict, List
import re
from PIL import Image
import io
import base64
from .image_embedder import create_image_embedding

load_dotenv()

def clean_nmap_output(content: str) -> str:
    """Clean and structure nmap/scan output"""
    # Reference to Headless.MD for format
    lines = content.split('\n')
    cleaned = []
    for line in lines:
        # Remove SF: prefix and clean escape sequences
        line = re.sub(r'^SF:', '', line)
        line = re.sub(r'\\x20', ' ', line)
        line = re.sub(r'\\n', '\n', line)
        if line.strip():
            cleaned.append(line.strip())
    return ' '.join(cleaned)

def extract_directory_scan(content: str) -> List[Dict]:
    """Extract directory scanning results"""
    # Reference to Monitored.MD for format
    results = []
    pattern = r'(\S+)\s+\[Status:\s+(\d+),\s+Size:\s+(\d+)'
    
    for match in re.finditer(pattern, content):
        results.append({
            'path': match.group(1),
            'status': match.group(2),
            'size': match.group(3)
        })
    return results

def create_chroma_collection():
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

def process_markdown_content(file_path: str) -> Dict:
    """Process markdown file content for embedding"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        # Extract title from first line if it starts with #
        title = content.split('\n')[0].replace('#', '').strip()
        
        # Remove image tags
        content = re.sub(r'!\[.*?\]\(.*?\)', '', content)
        
        # Remove code blocks
        content = re.sub(r'```.*?```', '', content, flags=re.DOTALL)
        
        return {
            "content": content.strip(),
            "metadata": {
                "title": title,
                "source": str(file_path),
                "type": "markdown"
            }
        }
    except Exception as e:
        print(f"Error processing markdown {file_path}: {e}")
        return None

def process_all_content():
    collection = create_chroma_collection()
    
    # Process markdown files
    markdown_dir = Path("data/raw/writeups")
    if markdown_dir.exists():
        for md_file in markdown_dir.glob("*.MD"):
            processed = process_markdown_content(md_file)
            if processed:
                collection.add(
                    documents=[processed["content"]],
                    metadatas=[processed["metadata"]],
                    ids=[f"md_{hash(processed['content'])}"[:64]]
                )
                print(f"Processed markdown: {md_file.name}")
    
    # Process images using GPT-4-Vision
    metadata_file = Path("data/processed/images/metadata.jsonl")
    if metadata_file.exists():
        with open(metadata_file) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    embedding = create_image_embedding(
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