from pathlib import Path
from ..embeddings.unified_processor import process_all_content, create_chroma_collection

def main():
    print("Starting content embedding process...")

    # Process both markdown and images using unified processor
    print("\nProcessing all content...")
    process_all_content()
    
    # Verify collection
    collection = create_chroma_collection()
    count = collection.count()
    print(f"\nTotal documents in collection: {count}")

if __name__ == "__main__":
    main()