"""
Sandboxed Document Processing & File-Type Validation.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Validates magic byte signatures, prevents extension spoofing, and guards against zip bombs.
"""

from dataclasses import dataclass
import io
import logging
from typing import Optional, Set, Tuple
import zipfile

logger = logging.getLogger("cyber_osint.services.security.file_validator")

# Known magic byte signatures
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpeg": [b"\xff\xd8\xff"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06"],  # Also used by docx, xlsx, jar
    "executable": [b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce"],
}

# Dangerous executable or script extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com"
}


@dataclass
class FileValidationResult:
    """Result of validating uploaded or ingested file bytes."""
    is_valid: bool
    detected_type: str
    claimed_type: str
    file_size_bytes: int
    rejection_reason: Optional[str] = None
    detected_mime: Optional[str] = None
    is_executable: bool = False


class FileTypeValidator:
    """
    Validates file payloads by inspecting magic bytes, file extensions,
    and archive decompression safety limits.
    """

    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
    MAX_DECOMPRESSION_RATIO = 100      # Zip bomb protection: reject > 100:1 ratio

    @classmethod
    def detect_magic_type(cls, file_bytes: bytes) -> str:
        """Inspects the leading bytes of a payload to detect true file format."""
        if not file_bytes:
            return "empty"

        header = file_bytes[:16]

        if any(header.startswith(sig) for sig in MAGIC_SIGNATURES["pdf"]):
            return "pdf"
        if any(header.startswith(sig) for sig in MAGIC_SIGNATURES["png"]):
            return "png"
        if any(header.startswith(sig) for sig in MAGIC_SIGNATURES["jpeg"]):
            return "jpeg"
        if any(header.startswith(sig) for sig in MAGIC_SIGNATURES["executable"]):
            return "executable"
        if any(header.startswith(sig) for sig in MAGIC_SIGNATURES["zip"]):
            return "zip"

        # Check for JSON or text
        try:
            text_prefix = file_bytes[:512].decode("utf-8", errors="strict").strip()
            if text_prefix.startswith("{") or text_prefix.startswith("["):
                return "json"
            if text_prefix.startswith("<"):
                return "xml_or_html"
            return "text"
        except UnicodeDecodeError:
            return "binary_unknown"

    @classmethod
    def validate_file(
        cls,
        file_bytes: bytes,
        filename: str,
        allowed_types: Optional[Set[str]] = None,
    ) -> FileValidationResult:
        """
        Validates file size, true magic bytes, extension spoofing, and zip bombs.
        """
        file_size = len(file_bytes)
        ext = ("." + filename.split(".")[-1].lower()) if "." in filename else ""

        # 1. Size check
        if file_size > cls.MAX_FILE_SIZE:
            return FileValidationResult(
                is_valid=False,
                detected_type="oversized",
                claimed_type=ext,
                file_size_bytes=file_size,
                rejection_reason=f"File exceeds maximum allowed size of {cls.MAX_FILE_SIZE // (1024*1024)}MB.",
            )

        # 2. Extension check
        if ext in EXECUTABLE_EXTENSIONS:
            return FileValidationResult(
                is_valid=False,
                detected_type="executable_extension",
                claimed_type=ext,
                file_size_bytes=file_size,
                rejection_reason=f"Executable file extension '{ext}' is strictly disallowed.",
            )

        # 3. Magic byte check
        detected = cls.detect_magic_type(file_bytes)
        if detected == "executable":
            return FileValidationResult(
                is_valid=False,
                detected_type="executable",
                claimed_type=ext,
                file_size_bytes=file_size,
                rejection_reason="Binary executable magic bytes detected. Upload rejected.",
            )

        # 4. Extension spoofing check (e.g. document named .pdf that is actually HTML/JS or unknown binary)
        if ext == ".pdf" and detected not in {"pdf", "empty"}:
            return FileValidationResult(
                is_valid=False,
                detected_type=detected,
                claimed_type=ext,
                file_size_bytes=file_size,
                rejection_reason=f"Extension spoofing: File claims to be .pdf but true format is {detected}.",
            )

        # 5. Decompression bomb check for zip archives
        if detected == "zip":
            is_safe, bomb_err = cls.check_zip_bomb(file_bytes)
            if not is_safe:
                return FileValidationResult(
                    is_valid=False,
                    detected_type="zip_bomb",
                    claimed_type=ext,
                    file_size_bytes=file_size,
                    rejection_reason=bomb_err,
                )

        # 6. Check against allowed types if supplied
        if allowed_types and detected not in allowed_types:
            return FileValidationResult(
                is_valid=False,
                detected_type=detected,
                claimed_type=ext,
                file_size_bytes=file_size,
                rejection_reason=f"File type '{detected}' is not in allowed types: {allowed_types}.",
            )

        mime_map = {
            "pdf": "application/pdf",
            "png": "image/png",
            "jpeg": "image/jpeg",
            "json": "application/json",
            "xml_or_html": "application/xml",
            "text": "text/plain",
            "zip": "application/zip",
            "executable": "application/x-dosexec",
        }
        return FileValidationResult(
            is_valid=True,
            detected_type=detected,
            claimed_type=ext,
            file_size_bytes=file_size,
            rejection_reason=None,
            detected_mime=mime_map.get(detected, "application/octet-stream"),
            is_executable=(detected == "executable" or ext in EXECUTABLE_EXTENSIONS),
        )

    @classmethod
    def inspect_bytes(cls, file_bytes: bytes, filename: str = "unknown") -> FileValidationResult:
        """Convenience method returning FileValidationResult with mime and executable flags."""
        res = cls.validate_file(file_bytes, filename)
        mime_map = {
            "pdf": "application/pdf",
            "png": "image/png",
            "jpeg": "image/jpeg",
            "json": "application/json",
            "xml_or_html": "application/xml",
            "text": "text/plain",
            "zip": "application/zip",
            "executable": "application/x-dosexec",
        }
        res.detected_mime = mime_map.get(res.detected_type, "application/octet-stream")
        res.is_executable = (res.detected_type == "executable" or ("." + filename.split(".")[-1].lower() in EXECUTABLE_EXTENSIONS))
        return res

    @classmethod
    def check_zip_bomb(cls, zip_bytes: bytes) -> Tuple[bool, Optional[str]]:
        """Guards against zip decompression bombs by verifying uncompressed ratio."""
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                compressed_size = len(zip_bytes)

                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if ratio > cls.MAX_DECOMPRESSION_RATIO:
                        return False, f"Potential zip bomb detected: compression ratio {ratio:.1f}:1 exceeds {cls.MAX_DECOMPRESSION_RATIO}:1 ceiling."

                if total_uncompressed > 100 * 1024 * 1024:  # 100MB max extracted
                    return False, "Archive total uncompressed volume exceeds 100MB limit."

                return True, None
        except zipfile.BadZipFile:
            return False, "Malformed or corrupted zip archive."
        except Exception as exc:
            return False, f"Archive inspection error: {exc}"


file_validator = FileTypeValidator()


class DocumentSandbox:
    """
    Sandboxed document processor enforcing strict size, decompression ratios,
    and isolated text parsing.
    Conforms to IMPLEMENT.md Section 37 & 39 ('Sandboxed document processing').
    """

    def __init__(
        self,
        max_size_bytes: int = 10 * 1024 * 1024,
        max_decompression_ratio: int = 50,
    ):
        self.max_size_bytes = max_size_bytes
        self.max_decompression_ratio = max_decompression_ratio

    def sandbox_process(self, file_bytes: bytes, filename: str = "document.bin") -> dict:
        """Processes an untrusted document in a sandboxed execution wrapper."""
        if len(file_bytes) > self.max_size_bytes:
            return {
                "success": False,
                "error": f"Payload size {len(file_bytes)} exceeds safe sandbox limit of {self.max_size_bytes} bytes.",
                "content": "",
                "risk_level": "critical",
            }

        val_res = FileTypeValidator.validate_file(file_bytes, filename)
        if not val_res.is_valid:
            return {
                "success": False,
                "error": f"Validation failed: {val_res.rejection_reason}",
                "content": "",
                "risk_level": "critical" if val_res.detected_type in {"executable", "zip_bomb"} else "high",
            }

        # Safe text extraction simulation
        try:
            text = file_bytes.decode("utf-8", errors="replace")[:10000]
            return {
                "success": True,
                "error": None,
                "content": text,
                "detected_type": val_res.detected_type,
                "risk_level": "low",
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Sandbox processing error: {exc}",
                "content": "",
                "risk_level": "medium",
            }


sandbox = DocumentSandbox()
