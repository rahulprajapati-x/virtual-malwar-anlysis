import math
from pathlib import Path

def calculate_chunk_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_full_entropy(file_path: Path, chunk_size: int = 4096) -> dict:
    """
    Computes a chunk-by-chunk entropy map across the entire file.
    Returns:
    - map: list of entropy values per chunk
    - is_packed: bool if significant portion is high entropy
    - overall_entropy: float
    """
    chunk_entropies = []
    total_data = b""
    high_entropy_chunks = 0
    
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_data += chunk
                ent = calculate_chunk_entropy(chunk)
                chunk_entropies.append(round(ent, 2))
                if ent > 7.0:
                    high_entropy_chunks += 1
                    
        overall_entropy = calculate_chunk_entropy(total_data)
        total_chunks = len(chunk_entropies)
        is_packed = False
        
        # Heuristic for packing: overall entropy > 7.2 or >50% chunks are high entropy
        if total_chunks > 0:
            if overall_entropy > 7.2 or (high_entropy_chunks / total_chunks) > 0.5:
                is_packed = True
                
        # Limit max returned chunks to prevent huge payload for very large files
        if len(chunk_entropies) > 1000:
            step = len(chunk_entropies) // 1000
            chunk_entropies = chunk_entropies[::step]
            
        return {
            "entropy_map": chunk_entropies,
            "overall_entropy": round(overall_entropy, 2),
            "is_packed": is_packed,
            "high_entropy_chunks": high_entropy_chunks
        }
    except Exception as e:
        return {
            "entropy_map": [],
            "overall_entropy": 0.0,
            "is_packed": False,
            "high_entropy_chunks": 0,
            "error": str(e)
        }
