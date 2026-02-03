import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

@dataclass
class Attachment:
    """File to include in an e-adrese message."""

    filename: str
    content: bytes
    content_type: str = "application/octet-stream"

    @classmethod
    def from_file(cls, path: Path, content_type: Optional[str] = None) -> "Attachment":
        data = path.read_bytes()
        ctype = content_type or _guess_mime(path.suffix)
        return cls(filename=path.name, content=data, content_type=ctype)

    def to_payload(self) -> Mapping[str, str]:
        return {
            "FileName": self.filename,
            "ContentType": self.content_type,
            "Content": base64.b64encode(self.content).decode("ascii"),
        }

    def sha256_digest(self) -> bytes:
        import hashlib
        return hashlib.sha256(self.content).digest()

    def sha512_digest(self) -> bytes:
        import hashlib
        return hashlib.sha512(self.content).digest()

def _guess_mime(ext: str) -> str:
    mime_map = {
        ".xml": "application/xml",
        ".pdf": "application/pdf",
        ".txt": "text/plain",
    }
    return mime_map.get(ext.lower(), "application/octet-stream")
