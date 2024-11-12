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

def process_image_with_context(entry: Dict) -> Dict:
    """Process image with its surrounding context"""
    try:
        # Load and encode image
        with Image.open(entry["local_path"]) as img:
            buffered = io.BytesIO()
            img.save(buffered, format=img.format)
            img_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        # Extract meaningful context
        context = entry["context"]
        # Clean markdown image tags
        context = re.sub(r'!\[.*?\]\(.*?\)', '', context)
        
        return {
            "content": context.strip(),
            "metadata": {
                "title": entry["title"],
                "source": entry["source_file"],
                "type": "image",
                "image_data": img_base64,
                "local_path": entry["local_path"]
            }
        }
    except Exception as e:
        print(f"Error processing image {entry['local_path']}: {e}")
        return None

def create_chroma_collection():
    client = chromadb.PersistentClient(path="data/chroma")
    
    embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.getenv("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    
    try:
        return client.get_collection("security_content", embedding_fn)
    except ValueError:
        return client.create_collection("security_content", embedding_fn)

def process_content():
    collection = create_chroma_collection()
    
    # Process images and their context
    metadata_file = Path("data/processed/images/metadata.jsonl")
    if metadata_file.exists():
        with open(metadata_file) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    processed = process_image_with_context(entry)
                    if processed:
                        collection.add(
                            documents=[processed["content"]],
                            metadatas=[processed["metadata"]],
                            ids=[f"img_{hash(processed['content'])}"[:64]]
                        )

def query_content(query: str, n_results: int = 5):
    collection = create_chroma_collection()
    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        include=["documents", "metadatas"]
    )
    return results

if __name__ == "__main__":
    process_content()