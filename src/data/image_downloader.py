from pathlib import Path
import aiohttp
import aiofiles
import asyncio
import re
from typing import List, Dict
import os
from PIL import Image
import io

async def download_github_image(url: str, save_dir: Path, filename: str) -> str:
    """Download image from GitHub and save as PNG"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                # Create directory if it doesn't exist
                save_dir.mkdir(parents=True, exist_ok=True)
                
                # Read image data
                img_data = await response.read()
                
                # Convert to PNG using PIL
                img = Image.open(io.BytesIO(img_data))
                save_path = save_dir / f"{filename}.png"
                img.save(save_path, "PNG")
                
                return str(save_path)
    return ""

async def process_markdown_for_images(md_file: Path) -> List[Dict]:
    """Extract GitHub images from markdown file"""
    async with aiofiles.open(md_file, 'r') as f:
        content = await f.read()
    
    images = []
    # Match GitHub image markdown pattern
    pattern = r'!\[(.*?)\]\((https://github\.com/[^)]+)\)'
    
    for match in re.finditer(pattern, content):
        images.append({
            "title": match.group(1),
            "url": match.group(2),
            "source_file": str(md_file)
        })
    
    return images

async def main():
    # Setup directories
    base_dir = Path("data")
    images_dir = base_dir / "processed" / "images"
    writeups_dir = Path("src/data/raw/writeups")
    
    # Process each markdown file
    for md_file in writeups_dir.glob("*.MD"):
        print(f"Processing {md_file.name}")
        images = await process_markdown_for_images(md_file)
        
        for idx, img in enumerate(images):
            writeup_name = md_file.stem
            save_dir = images_dir / writeup_name
            
            # Download and save image
            saved_path = await download_github_image(
                img["url"],
                save_dir,
                f"image_{idx}"
            )
            
            if saved_path:
                print(f"Downloaded: {saved_path}")
                
                # Save metadata
                async with aiofiles.open(images_dir / "metadata.jsonl", 'a') as f:
                    await f.write(f'{{"path": "{saved_path}", "title": "{img["title"]}", "source": "{img["source_file"]}", "url": "{img["url"]}"}}\n')

if __name__ == "__main__":
    asyncio.run(main())