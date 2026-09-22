"""
CyberForge — Hash Engine
Computes all cryptographic and fuzzy hashes for submitted samples.
"""
import hashlib
import math
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str
    sha512: str
    imphash: Optional[str] = None       # PE import hash
    ssdeep: Optional[str] = None        # Fuzzy hash
    file_size: int = 0

    def to_dict(self) -> dict:
        return {
            "md5":      self.md5,
            "sha1":     self.sha1,
            "sha256":   self.sha256,
            "sha512":   self.sha512,
            "imphash":  self.imphash,
            "ssdeep":   self.ssdeep,
            "file_size": self.file_size,
        }


def compute_hashes(file_path: Path) -> HashResult:
    """
    Compute all hash types for a file.
    Reads the file in chunks to handle large files efficiently.
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    file_size = 0
    chunk_size = 65536  # 64KB chunks

    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            file_size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    # Try fuzzy hashing (ssdeep — optional dep)
    ssdeep_hash = None
    try:
        import ssdeep
        ssdeep_hash = ssdeep.hash_from_file(str(file_path))
    except (ImportError, Exception):
        pass

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest(),
        ssdeep=ssdeep_hash,
        file_size=file_size,
    )


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    High entropy (>7.0) suggests encryption or compression.
    Used for detecting packed/encrypted PE sections.
    """
    if not data:
        return 0.0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_section_entropy(file_path: Path, offset: int, size: int) -> float:
    """Read a section of a file and compute its entropy."""
    with open(file_path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    return calculate_entropy(data)
