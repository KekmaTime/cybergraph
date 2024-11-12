from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
from datetime import datetime
import json
import base64
from xml.dom.minidom import Document
from PIL import Image
import io
import aiohttp
import aiofiles
import re
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from ..graph.graph_builder import GraphBuilder

class SecurityImageAnalysis(BaseModel):
    """Structure for security image analysis results."""
    hosts: List[Dict[str, Any]] = []
    ports: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    vulnerabilities: List[Dict[str, Any]] = []
    description: str = ""
    context: str = ""

class SecurityImageProcessor:
    """Processes security-related images and integrates with GraphBuilder."""
    
    def __init__(self, graph_builder: GraphBuilder):
        self.graph_builder = graph_builder
        self.vision_model = ChatOpenAI(
            model="gpt-4o-mini",
            max_tokens=1000,
            temperature=0
        )
        self.logger = logging.getLogger(__name__)
        self.metrics = {
            "image_processing_time": [],
            "graph_storage_time": [],
            "vector_storage_time": []
        }
    
    async def _download_image(self, url: str, save_path: Path) -> bool:
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
            logging.error(f"Error downloading {url}: {e}")
            return False
            
    async def process_markdown_images(self, file_path: Path) -> List[Dict]:
        """Extract and download images from markdown file"""
        async with aiofiles.open(file_path, 'r') as f:
            content = await f.read()
        
        images = []
        pattern = r'!\[(.*?)\]\((https://github\.com/[^)]+)\)'
        
        for match in re.finditer(pattern, content):
            title = match.group(1)
            url = match.group(2)
            
            filename = re.sub(r'[^\w]', '_', title) or url.split('/')[-1]
            save_path = Path('data/processed/images') / file_path.stem / f"{filename}.png"
            
            if await self._download_image(url, save_path):
                # Process and store in graph
                image_id = self.process_and_store_image(
                    str(save_path),
                    content[max(0, match.start()-100):match.end()+100]
                )
                
                if image_id:
                    result = {
                        'title': title,
                        'url': url,
                        'local_path': str(save_path),
                        'source_file': str(file_path),
                        'image_id': image_id,
                        'timestamp': datetime.now().isoformat()
                    }
                    images.append(result)
                    
                    # Save metadata
                    async with aiofiles.open('data/processed/images/metadata.jsonl', 'a') as f:
                        await f.write(json.dumps(result) + '\n')
        
        return images
    
    async def process_and_store_image(self, image_path: str, context: str = "") -> Optional[str]:
        """Process image and store results in graph database."""
        try:
            # Get image analysis
            analysis = await self._analyze_image(image_path, context)
            if not analysis:
                return None
            
            # Create image node and relationships
            image_id = await self._store_in_graph(analysis, image_path)
            
            # Add to vector store for searchability
            await self._store_in_vector(analysis, image_id)
            
            return image_id
            
        except Exception as e:
            logging.error(f"Error processing image {image_path}: {str(e)}")
            Documentone
    
    def _analyze_image(self, image_path: str, context: str) -> Optional[Dict]:
        """Analyze image using GPT-4 Vision."""
        try:
            with Image.open(image_path) as image:
                buffered = io.BytesIO()
                image.save(buffered, format=image.format or "JPEG")
                base64_image = base64.b64encode(buffered.getvalue()).decode()
            
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": self._generate_prompt(context)},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ]
            
            response = self.vision_model.invoke(messages)
            return json.loads(response.content)
            
        except Exception as e:
            logging.error(f"Error analyzing image: {str(e)}")
            return None
    
    def _store_in_graph(self, analysis: Dict, image_path: str) -> str:
        """Enhanced graph storage with relationship processing."""
        query = """
        CREATE (i:Image {
            id: randomUUID(),
            path: $path,
            timestamp: $timestamp,
            description: $description
        })
        WITH i
        UNWIND $hosts as host
        MERGE (h:Host {id: host.id})
        SET h += host.properties
        MERGE (h)-[:SHOWN_IN]->(i)
        WITH i, h
        UNWIND $ports as port
        MERGE (p:Port {id: h.id + ':' + toString(port.number)})
        SET p += port
        MERGE (h)-[:HAS_PORT]->(p)
        WITH i, p
        UNWIND $services as service
        MERGE (s:Service {id: p.id + ':' + service.name})
        SET s += service
        MERGE (p)-[:RUNS_SERVICE]->(s)
        WITH i, h
        UNWIND $vulnerabilities as vuln
        MERGE (v:Vulnerability {id: h.id + ':' + vuln.name})
        SET v += vuln
        MERGE (h)-[:HAS_VULNERABILITY]->(v)
        RETURN i.id as image_id
        """
        
        result = self.graph_builder.graph.query(
            query,
            {
                "path": str(image_path),
                "timestamp": datetime.now().isoformat(),
                "description": analysis["description"],
                "hosts": analysis["hosts"],
                "ports": analysis["ports"],
                "services": analysis["services"],
                "vulnerabilities": analysis["vulnerabilities"]
            }
        )
        
        return result[0]["image_id"]
    
    def _store_in_vector(self, analysis: Dict, image_id: str):
        """Store image analysis in vector store."""
        self.graph_builder.vector_store.add_documents([
            Document(
                page_content=analysis["description"],
                metadata={
                    "type": "security_image",
                    "image_id": image_id,
                    "timestamp": datetime.now().isoformat()
                }
            )
        ])
    
    def _generate_prompt(self, context: str) -> str:
        """Generate analysis prompt."""
        prompt = """Analyze this security-related image and extract:
        1. Hosts: List of hosts with IDs and properties
        2. Ports: Open ports and their states
        3. Services: Running services and versions
        4. Vulnerabilities: Security issues with severity
        
        Format as JSON:
        {
            "hosts": [{"id": "...", "properties": {...}}],
            "ports": [{"number": 0, "state": "..."}],
            "services": [{"name": "...", "version": "..."}],
            "vulnerabilities": [{"name": "...", "severity": "..."}],
            "description": "..."
        }"""
        
        if context:
            prompt = f"Context: {context}\n\n{prompt}"
        
        return prompt
    
    def _encode_image(self, image_path: str) -> str:
        """Encode image to base64 string."""
        with Image.open(image_path) as image:
            buffered = io.BytesIO()
            image.save(buffered, format=image.format or "JPEG")
            return base64.b64encode(buffered.getvalue()).decode()
    
    def update_image_analysis(self, image_path: str, context: str = "") -> Optional[str]:
        """Update existing image analysis with version tracking."""
        try:
            analysis = self._analyze_image(image_path, context)
            if not analysis:
                return None
                
            # Use GraphBuilder's update mechanism
            self.graph_builder.update_security_data({
                "image_path": image_path,
                "analysis": analysis,
                "last_check": datetime.now().isoformat()
            }, "image_analysis")
            
            return image_path
            
        except Exception as e:
            logging.error(f"Error updating image analysis {image_path}: {str(e)}")
            return None
    
    async def create_image_embedding(self, image_path: str, context: str = "") -> Optional[Dict]:
        """Create embeddings for image analysis results."""
        try:
            analysis = await self._analyze_image(image_path, context)
            if not analysis:
                return None
                
            return {
                "description": analysis["description"],
                "analysis": analysis
            }
            
        except Exception as e:
            logging.error(f"Error creating image embedding: {str(e)}")
            return None
    
    async def process_markdown_content(self, file_path: Path) -> Optional[Dict]:
        """Process markdown content and extract metadata."""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                
            return {
                "content": content,
                "metadata": {
                    "source": str(file_path),
                    "type": "markdown",
                    "timestamp": datetime.now().isoformat()
                }
            }
        except Exception as e:
            logging.error(f"Error processing markdown {file_path}: {str(e)}")
            return None