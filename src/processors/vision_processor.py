import base64
from openai import OpenAI
from typing import Dict, List
import os
from dotenv import load_dotenv
import json

load_dotenv()

def encode_image_to_base64(image_path: str) -> str:
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def process_image(image_path: str, context: str = "") -> Dict:
    """
    Process an image with optional context from surrounding text
    Args:
        image_path: Path to the image file
        context: Optional context from the markdown text
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    base64_image = encode_image_to_base64(image_path)
    
    # Enhanced prompt with context
    prompt = "Analyze this security scan output or screenshot. "
    if context:
        prompt += f"Context from document: {context}. "
    prompt += "Extract key information about hosts, ports, services, and potential vulnerabilities. Format the response as JSON with the following structure: {hosts: [], ports: [], services: [], vulnerabilities: []}"
    
    response = client.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
        max_tokens=1000
    )
    
    try:
        return json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        return {
            "error": "Failed to parse JSON response",
            "raw_response": response.choices[0].message.content
        }