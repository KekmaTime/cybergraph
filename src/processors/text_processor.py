from typing import Dict, List
import re
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

def extract_ports_services(text: str) -> Dict:
    port_pattern = r'(\d+)/tcp\s+open\s+(\w+)'
    matches = re.findall(port_pattern, text)
    return {int(port): service for port, service in matches}

def extract_hostnames(text: str) -> List[str]:
    hostname_pattern = r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    return list(set(re.findall(hostname_pattern, text)))

def process_text(text: str) -> Dict:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": "Extract security-relevant information from scan outputs and format as JSON with hosts, ports, services, and vulnerabilities."
            },
            {
                "role": "user",
                "content": text
            }
        ],
        temperature=0
    )
    
    # Basic extraction
    ports_services = extract_ports_services(text)
    hostnames = extract_hostnames(text)
    
    # Combine with LLM analysis
    llm_analysis = response.choices[0].message.content
    
    return {
        "ports_services": ports_services,
        "hostnames": hostnames,
        "llm_analysis": llm_analysis
    }