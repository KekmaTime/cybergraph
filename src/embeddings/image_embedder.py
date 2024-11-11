from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions
from openai import OpenAI
import json
import base64
from typing import Dict, List
import os
from dotenv import load_dotenv

load_dotenv()

def create_image_embedding(image_path: str, context: str = "") -> Dict:
    """Create embedding for an image using GPT-4 Vision"""
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    # Read and encode image
    with open(image_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode('utf-8')
    
    # Get embedding with context
    response = client.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": f"Context: {context}\nAnalyze this security-related image and describe key details about hosts, ports, services, and vulnerabilities."
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
        max_tokens=300
    )
    
    return {
        "description": response.choices[0].message.content,
        "image_path": image_path,
        "context": context
    }

def setup_chroma_client():
    """Setup ChromaDB with OpenAI embeddings"""
    client = chromadb.Client()
    
    # Create collections
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.getenv("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    
    images_collection = client.create_collection(
        name="security_images",
        embedding_function=openai_ef
    )
    
    text_collection = client.create_collection(
        name="security_text",
        embedding_function=openai_ef
    )
    
    return images_collection, text_collection

def process_directory(base_dir: Path):
    """Process all images and text in the processed directory"""
    images_collection, text_collection = setup_chroma_client()
    
    # Process images
    images_dir = base_dir / "processed" / "images"
    metadata_file = images_dir / "metadata.jsonl"
    
    if metadata_file.exists():
        with open(metadata_file) as f:
            for line in f:
                img_data = json.loads(line)
                if "processed_path" in img_data:
                    embedding = create_image_embedding(
                        img_data["processed_path"],
                        img_data.get("context", "")
                    )
                    
                    images_collection.add(
                        documents=[embedding["description"]],
                        metadatas=[{
                            "source_file": img_data["source_file"],
                            "image_path": img_data["processed_path"],
                            "context": img_data.get("context", "")
                        }],
                        ids=[img_data["id"]]
                    )
    
    # Process text chunks
    text_file = base_dir / "processed" / "text" / "chunks.jsonl"
    if text_file.exists():
        with open(text_file) as f:
            for line in f:
                chunk = json.loads(line)
                text_collection.add(
                    documents=[chunk["content"]],
                    metadatas=[{
                        "type": chunk["type"],
                        "source_file": chunk["source_file"]
                    }],
                    ids=[chunk["id"]]
                )