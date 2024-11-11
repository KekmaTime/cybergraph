from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions
from openai import OpenAI
import json
import base64
from typing import Dict
import os
from dotenv import load_dotenv

load_dotenv()

def create_image_embedding(image_path: str, context: str = "") -> Dict:
    """Create embedding for an image using GPT-4-Vision mini"""
    if not Path(image_path).exists():
        print(f"Warning: Image not found: {image_path}")
        return None
        
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    try:
        with open(image_path, "rb") as image_file:
            base64_image = base64.b64encode(image_file.read()).decode('utf-8')
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": f"Context: {context}\nAnalyze this security-related image and describe key details about hosts, ports, services, and vulnerabilities shown."},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{base64_image}",
                                "detail": "low"
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
    except Exception as e:
        print(f"Error processing {image_path}: {str(e)}")
        return None

def process_images_to_chroma():
    client = chromadb.PersistentClient(path="data/chroma")
    
    embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.getenv("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    
    collection = client.create_collection(
        name="security_images",
        embedding_function=embedding_fn
    )
    
    metadata_file = Path("data/processed/images/metadata.jsonl")
    
    if metadata_file.exists():
        with open(metadata_file) as f:
            for line in f:
                if line.strip():
                    img_data = json.loads(line)
                    
                    # Use local_path instead of path
                    if not Path(img_data["local_path"]).exists():
                        print(f"Skipping missing image: {img_data['local_path']}")
                        continue
                        
                    embedding = create_image_embedding(
                        img_data["local_path"],
                        img_data.get("context", "")
                    )
                    
                    if embedding:
                        collection.add(
                            documents=[embedding["description"]],
                            metadatas=[{
                                "source": img_data["source_file"],
                                "image_path": img_data["local_path"],
                                "title": img_data["title"],
                                "url": img_data["url"]
                            }],
                            ids=[img_data["local_path"]]
                        )
                        print(f"Processed: {img_data['local_path']}")

if __name__ == "__main__":
    process_images_to_chroma()