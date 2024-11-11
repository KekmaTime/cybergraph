from pathlib import Path
import aiohttp
import aiofiles
from PIL import Image
import io
import asyncio
from typing import Dict, Optional
import os

async def download_github_image(url: str, save_path: Path) -> Optional[Path]:
    """Download image from GitHub and convert to PNG"""
    try:
        # Convert GitHub asset URL to raw content URL
        raw_url = url.replace("github.com", "raw.githubusercontent.com")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(raw_url) as response:
                if response.status == 200:
                    image_data = await response.read()
                    
                    # Convert to PNG using Pillow
                    image = Image.open(io.BytesIO(image_data))
                    
                    # Create standardized filename
                    png_path = save_path / f"{save_path.stem}.png"
                    
                    # Save as PNG
                    image.save(png_path, "PNG", optimize=True)
                    return png_path
                return None
    except Exception as e:
        print(f"Error processing image {url}: {str(e)}")
        return None

async def process_writeup_images(image_info: Dict, base_dir: Path) -> Dict:
    """Process all images from a writeup"""
    # Create images directory if it doesn't exist
    images_dir = base_dir / "processed" / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    
    # Create directory for this specific writeup
    writeup_name = Path(image_info["source_file"]).stem
    writeup_images_dir = images_dir / writeup_name
    writeup_images_dir.mkdir(exist_ok=True)
    
    # Download and process image
    if image_info["type"] == "github_image":
        saved_path = await download_github_image(
            image_info["url"], 
            writeup_images_dir / image_info["id"]
        )
        if saved_path:
            image_info["processed_path"] = str(saved_path)
    
    return image_info