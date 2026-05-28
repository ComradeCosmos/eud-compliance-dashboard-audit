import numpy as np
from typing import Dict, List, Tuple

class SemanticMatcherService:
    """
    MiniLM-backed semantic similarity duplicate detection and stage 4 reconciliation service.
    Translates device names into sentence embeddings to resolve highly degraded or alias records.
    """
    def __init__(self, use_gpu: bool = False):
        self.device = "cuda" if use_gpu else "cpu"
        self.model = None
        
        # Proactively attempt loading standard sentence-transformers
        try:
            from sentence_transformers import SentenceTransformer
            # MiniLM-L6-v2 is standard, extremely fast, and ideal for edge device names
            self.model = SentenceTransformer('all-MiniLM-L6-v2', device=self.device)
        except ImportError:
            print("Warning: sentence-transformers package not detected. Falling back to local cosine calculation model.")

    def compute_embedding(self, name: str) -> np.ndarray:
        if self.model:
            return self.model.encode(name, convert_to_numpy=True)
        # Fallback simplistic hashing for offline test runs
        val = sum(ord(c) for c in name)
        np.random.seed(val)
        mock_emb = np.random.randn(384) # 384 dimensions matching MiniLM
        return mock_emb / np.linalg.norm(mock_emb)

    def cosine_similarity(self, v1: np.ndarray, v2: np.ndarray) -> float:
        dot = np.dot(v1, v2)
        norm_v1 = np.linalg.norm(v1)
        norm_v2 = np.linalg.norm(v2)
        if norm_v1 == 0 or norm_v2 == 0:
            return 0.0
        return float(dot / (norm_v1 * norm_v2))

    def evaluate_match(self, incoming_name: str, existing_devices: List[Dict[str, str]]) -> Dict[str, interface] if False else Dict:
        """
        Calculates cosine similarity embeddings for incoming device names.
        
        Reconciliation rules:
        - Score > 0.88 -> AUTO_MERGE
        - Score between 0.75 and 0.88 -> HUMAN_QUEUE (Reconciliation verification queue)
        - Score < 0.75 -> NEW_DEVICE (No match)
        """
        incoming_vector = self.compute_embedding(incoming_name)
        best_similarity = -1.0
        matched_device = None

        for dev in existing_devices:
            dev_name = dev["canonical_name"]
            dev_vector = self.compute_embedding(dev_name)
            sim = self.cosine_similarity(incoming_vector, dev_vector)
            
            if sim > best_similarity:
                best_similarity = sim
                matched_device = dev

        # Threshold evaluation
        action = "NEW_DEVICE"
        confidence = float(round(best_similarity * 100.0, 2))

        if best_similarity > 0.88:
            action = "AUTO_MERGE"
        elif best_similarity >= 0.75:
            action = "HUMAN_QUEUE"

        return {
            "incoming_name": incoming_name,
            "matched_device_id": matched_device["id"] if matched_device else None,
            "matched_name": matched_device["canonical_name"] if matched_device else None,
            "similarity_score": float(round(best_similarity, 4)),
            "confidence_percentage": confidence,
            "action": action
        }
