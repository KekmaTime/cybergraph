from pathlib import Path
from typing import List
from .ingestion import process_markdown_file, setup_data_storage, store_processed_data
import asyncio

async def process_writeups_directory(writeups_dir: str) -> None:
    """Process all markdown files in the writeups directory"""
    base_dir = setup_data_storage()
    
    # Process each markdown file
    for md_file in Path(writeups_dir).glob("**/*.md"):
        print(f"Processing: {md_file}")
        try:
            text_chunks, image_info = process_markdown_file(md_file)
            await store_processed_data(text_chunks, image_info, base_dir)
        except Exception as e:
            print(f"Error processing {md_file}: {str(e)}")

# Run with asyncio
if __name__ == "__main__":
    asyncio.run(process_writeups_directory("src/data/raw/writeups"))
