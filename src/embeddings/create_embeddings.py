from pathlib import Path
from .image_embedder import process_directory

def main():
    base_dir = Path("data")
    process_directory(base_dir)

if __name__ == "__main__":
    main()