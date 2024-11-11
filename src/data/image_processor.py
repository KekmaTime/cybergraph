from pathlib import Path
import aiohttp
import aiofiles
import asyncio
import re
from typing import List, Dict
import json
from PIL import Image
import io

async def download_image(url: str, save_path: Path) -> bool:
    """Download image from GitHub URL"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    img_data = await response.read()
                    img = Image.open(io.BytesIO(img_data))
                    save_path.parent.mkdir(parents=True, exist_ok=True)
                    img.save(save_path, format='PNG')
                    return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
    return False

async def process_markdown_images(file_path: Path) -> List[Dict]:
    """Extract and download images from markdown file"""
    async with aiofiles.open(file_path, 'r') as f:
        content = await f.read()
    
    images = []
    pattern = r'!\[(.*?)\]\((https://github\.com/[^)]+)\)'
    
    for match in re.finditer(pattern, content):
        title = match.group(1)
        url = match.group(2)
        
        # Create unique filename from title or URL
        filename = re.sub(r'[^\w]', '_', title) or url.split('/')[-1]
        save_path = Path('data/processed/images') / file_path.stem / f"{filename}.png"
        
        images.append({
            'title': title,
            'url': url,
            'local_path': str(save_path),
            'source_file': str(file_path),
            'context': content[max(0, match.start()-100):match.end()+100]
        })
        
        # Download image
        if await download_image(url, save_path):
            print(f"Downloaded: {save_path}")
            
            # Save metadata
            async with aiofiles.open('data/processed/images/metadata.jsonl', 'a') as f:
                await f.write(json.dumps(images[-1]) + '\n')

async def main():
    writeups_dir = Path('data/raw/writeups')
    
    # Process each markdown file
    for md_file in writeups_dir.glob('*.MD'):
        print(f"\nProcessing: {md_file}")
        await process_markdown_images(md_file)

if __name__ == '__main__':
    asyncio.run(main())