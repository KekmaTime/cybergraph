import json
from pathlib import Path
import re
import shutil
from typing import Dict, List, Tuple
import markdown
from bs4 import BeautifulSoup
import uuid
import aiohttp
import aiofiles

from data.image_processor import process_writeup_images

def extract_scan_data(text: str) -> Dict:
    """Extract information from nmap or fuzzing outputs"""
    scan_data = {
        "ports": [],
        "services": [],
        "urls": [],
        "status_codes": []
    }
    
    # Extract ports and services (nmap style)
    port_pattern = r'(\d+)/(?:tcp|udp)\s+(?:open|filtered|closed)\s+(\w+)'
    for port, service in re.findall(port_pattern, text):
        scan_data["ports"].append(int(port))
        scan_data["services"].append(service)
    
    # Extract fuzzing results
    fuzzing_pattern = r'\[(Status: (\d+).*?Duration: (\d+)ms)\]'
    for match in re.findall(fuzzing_pattern, text):
        scan_data["status_codes"].append(int(match[1]))
    
    return scan_data

def get_surrounding_text(content: str, img_position: int, window: int = 300) -> str:
    """Get text surrounding an image markdown tag with larger context"""
    lines = content.split('\n')
    img_line = 0
    current_pos = 0
    
    # Find the line number containing the image
    for i, line in enumerate(lines):
        current_pos += len(line) + 1
        if current_pos >= img_position:
            img_line = i
            break
    
    # Get context lines
    start_line = max(0, img_line - 5)
    end_line = min(len(lines), img_line + 5)
    
    return '\n'.join(lines[start_line:end_line])

def process_markdown_file(file_path: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    Process a markdown file and extract text and images
    Returns: Tuple of (text_chunks, image_info)
    """
    # Read markdown content
    content = file_path.read_text()
    
    text_chunks = []
    image_info = []
    
    # Split content into chunks based on markdown headers and code blocks
    chunks = re.split(r'(^#{1,6}\s.*$|^```.*?```)', content, flags=re.MULTILINE | re.DOTALL)
    
    for chunk in chunks:
        if chunk.strip():
            chunk_id = str(uuid.uuid4())
            
            # Handle code blocks specially
            if chunk.startswith('```') and chunk.endswith('```'):
                scan_data = extract_scan_data(chunk)
                if any(scan_data.values()):
                    text_chunks.append({
                        "id": chunk_id,
                        "content": chunk,
                        "type": "scan_output",
                        "extracted_data": scan_data,
                        "source_file": str(file_path)
                    })
            else:
                text_chunks.append({
                    "id": chunk_id,
                    "content": chunk.strip(),
                    "type": "text",
                    "source_file": str(file_path)
                })
    
    # Extract GitHub-style images with context
    for match in re.finditer(r'!\[(.*?)\]\((https://github\.com/[^)]+)\)', content):
        img_title = match.group(1)
        img_url = match.group(2)
        context = get_surrounding_text(content, match.start())
        
        image_info.append({
            "id": str(uuid.uuid4()),
            "url": img_url,
            "title": img_title,
            "source_file": str(file_path),
            "type": "github_image",
            "context": context
        })
    
    return text_chunks, image_info

def setup_data_storage():
    """Create necessary directories for data storage"""
    base_dir = Path("data")
    (base_dir / "raw").mkdir(parents=True, exist_ok=True)
    (base_dir / "processed" / "text").mkdir(parents=True, exist_ok=True)
    (base_dir / "processed" / "images").mkdir(parents=True, exist_ok=True)
    return base_dir

async def store_processed_data(text_chunks: List[Dict], image_info: List[Dict], base_dir: Path):
    """Store processed text and images"""
    # Store text chunks
    text_file = base_dir / "processed" / "text" / "chunks.jsonl"
    async with aiofiles.open(text_file, 'a') as f:
        for chunk in text_chunks:
            await f.write(f"{json.dumps(chunk)}\n")
    
    # Process and store images
    processed_images = []
    for img in image_info:
        processed_img = await process_writeup_images(img, base_dir)
        processed_images.append(processed_img)
    
    # Store image metadata
    image_meta_file = base_dir / "processed" / "images" / "metadata.jsonl"
    async with aiofiles.open(image_meta_file, 'a') as f:
        for img in processed_images:
            await f.write(f"{json.dumps(img)}\n")