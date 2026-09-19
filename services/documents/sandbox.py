"""
Sandboxed Document Processing Pipeline & Worker Isolation.
Conforms strictly to IMPLEMENT.md Section 39 (Step 38: Sandboxed Document Processing).

Pipeline Architecture:
Worker
 ↓
Sandbox
 ↓
Parser
 ↓
Extracted text
 ↓
Sanitized result

Security Mandates:
- Do not process untrusted files directly inside the main API process.
- Never execute:
  1. Macros (VBA, XLM, Office macro-enabled projects)
  2. Embedded programs (PE executables, OLE binaries, PDF /Launch actions)
  3. Unknown binaries (unrecognized executable payloads, disguised binaries)
  during document ingestion.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import logging
import multiprocessing
import os
import re
import sys
import time
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import zipfile

from services.documents.models import DocumentMetadata, DocumentResult, DocumentType, RetentionMode

logger = logging.getLogger("cyber_osint.services.documents.sandbox")


class DocumentSandboxError(Exception):
    """Raised when an untrusted document violates security sandbox policies."""
    pass


class MacroExecutionBlockedError(DocumentSandboxError):
    """Raised when an ingested document contains prohibited active macros."""
    pass


class EmbeddedProgramBlockedError(DocumentSandboxError):
    """Raised when an ingested document contains prohibited embedded programs or launch actions."""
    pass


class UnknownBinaryBlockedError(DocumentSandboxError):
    """Raised when an ingested document contains an unrecognized binary payload or spoofed extension."""
    pass


@dataclass
class PipelineStageResult:
    """Audit record for an individual stage in the 5-stage document processing pipeline."""
    stage_name: str
    status: str  # "success", "failed", "blocked", "skipped"
    duration_ms: float
    details: Optional[str] = None


@dataclass
class DocumentSecurityScanResult:
    """Security audit evaluation identifying macros, embedded programs, and unknown binaries."""
    is_safe: bool
    detected_type: str
    macros_detected: List[str] = field(default_factory=list)
    embedded_programs_detected: List[str] = field(default_factory=list)
    unknown_binaries_detected: List[str] = field(default_factory=list)
    decompression_ratio: float = 1.0
    quarantine_status: str = "clean"  # "clean", "quarantined", "sanitized"
    rejection_reason: Optional[str] = None


@dataclass
class SanitizedDocumentResult:
    """Final sanitized document intelligence result produced by the 5-stage pipeline."""
    success: bool
    filename: str
    detected_type: str
    raw_text: str
    sanitized_text: str
    word_count: int
    char_count: int
    headings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    security_scan: Optional[DocumentSecurityScanResult] = None
    stages: List[PipelineStageResult] = field(default_factory=list)
    worker_pid: Optional[int] = None
    execution_time_ms: float = 0.0
    error: Optional[str] = None


class DocumentSecurityScanner:
    """
    Stage 2: Sandbox Security Scanner.
    Inspects untrusted documents before parser execution to identify and block:
    - Macros: VBA projects (vbaProject.bin), XLM macros, .docm/.xlsm/.pptm containers.
    - Embedded programs: Windows PE binaries (MZ), ELF binaries, OLE package executables,
      PDF /Launch actions, PDF /JavaScript actions.
    - Unknown binaries: Disguised binary executables or corrupted non-document files.
    - Decompression bombs: High compression ratios (>50:1) or excessive uncompressed volume (>100MB).
    """

    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB max payload
    MAX_DECOMPRESSION_RATIO = 50.0     # 50:1 max ratio
    MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB ceiling

    # Office OpenXML Macro and embedded container indicators
    MACRO_FILE_PATTERNS = [
        re.compile(r"vbaproject\.bin$", re.IGNORECASE),
        re.compile(r"vba.*\.bin$", re.IGNORECASE),
        re.compile(r"macrosheets?/", re.IGNORECASE),
        re.compile(r"xl/macrosheets/", re.IGNORECASE),
        re.compile(r"customizations\.xml$", re.IGNORECASE),
    ]

    EMBEDDED_PROGRAM_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr",
        ".com", ".pif", ".cpl", ".msi", ".jar", ".bin", ".elf",
        ".sh", ".py", ".dylib", ".so",
    }

    @classmethod
    def scan_document(cls, file_bytes: bytes, filename: str = "document.bin") -> DocumentSecurityScanResult:
        """
        Conducts deep static inspection of file bytes to detect macros, embedded programs,
        and unknown binaries without executing any document code.
        """
        if not file_bytes:
            return DocumentSecurityScanResult(
                is_safe=False,
                detected_type="empty",
                quarantine_status="quarantined",
                rejection_reason="Document payload is empty.",
            )

        if len(file_bytes) > cls.MAX_FILE_SIZE:
            return DocumentSecurityScanResult(
                is_safe=False,
                detected_type="oversized",
                quarantine_status="quarantined",
                rejection_reason=f"Document size ({len(file_bytes)} bytes) exceeds sandbox limit of {cls.MAX_FILE_SIZE} bytes.",
            )

        lower_fn = filename.lower()
        macros_detected: List[str] = []
        embedded_programs_detected: List[str] = []
        unknown_binaries: List[str] = []

        # 1. Inspect file header magic bytes
        header_type, is_executable_header = cls._identify_header(file_bytes)

        if is_executable_header:
            unknown_binaries.append(f"Executable binary header detected ({header_type}) disguised as document '{filename}'")
            return DocumentSecurityScanResult(
                is_safe=False,
                detected_type=header_type,
                unknown_binaries_detected=unknown_binaries,
                quarantine_status="quarantined",
                rejection_reason=f"Prohibited executable binary ({header_type}) detected. Never execute unknown binaries.",
            )

        # 2. Check Macro-enabled Office extensions
        if any(lower_fn.endswith(ext) for ext in [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"]):
            macros_detected.append(f"Macro-enabled Office extension detected: '{filename}'")

        # 3. PDF Deep Token Inspection
        if header_type == "pdf" or lower_fn.endswith(".pdf"):
            cls._scan_pdf(file_bytes, embedded_programs_detected, unknown_binaries)

        # 4. ZIP / Office OpenXML Deep Container Inspection (docx, pptx, xlsx, zip)
        elif header_type == "zip" or any(lower_fn.endswith(ext) for ext in [".docx", ".pptx", ".xlsx", ".zip"]):
            ratio_ok, ratio_val, ratio_err = cls._check_zip_bomb(file_bytes)
            if not ratio_ok:
                return DocumentSecurityScanResult(
                    is_safe=False,
                    detected_type="zip_bomb",
                    decompression_ratio=ratio_val,
                    quarantine_status="quarantined",
                    rejection_reason=ratio_err,
                )

            cls._scan_zip_container(file_bytes, macros_detected, embedded_programs_detected, unknown_binaries)

        # 5. OLE2 Compound Binary Inspection (.doc, .xls, .ppt)
        elif header_type == "ole2" or any(lower_fn.endswith(ext) for ext in [".doc", ".xls", ".ppt"]):
            cls._scan_ole2_container(file_bytes, macros_detected, embedded_programs_detected)

        # 6. Plain Text / HTML / Markdown Check
        elif header_type in {"html", "text", "markdown"}:
            # Check for binary injection inside supposed text files
            if b"\x00" in file_bytes[:4096]:
                unknown_binaries.append("Null-byte sequence in text header indicates disguised binary payload.")

        else:
            # Unrecognized binary format
            unknown_binaries.append(f"Unrecognized file format with binary signature '{file_bytes[:8].hex()}'.")

        # Determine overall safety
        has_macros = len(macros_detected) > 0
        has_embedded = len(embedded_programs_detected) > 0
        has_unknown = len(unknown_binaries) > 0

        if has_macros or has_embedded or has_unknown:
            reasons = []
            if has_macros:
                reasons.append(f"Macros detected ({len(macros_detected)} items)")
            if has_embedded:
                reasons.append(f"Embedded programs detected ({len(embedded_programs_detected)} items)")
            if has_unknown:
                reasons.append(f"Unknown binaries detected ({len(unknown_binaries)} items)")

            return DocumentSecurityScanResult(
                is_safe=False,
                detected_type=header_type,
                macros_detected=macros_detected,
                embedded_programs_detected=embedded_programs_detected,
                unknown_binaries_detected=unknown_binaries,
                quarantine_status="quarantined",
                rejection_reason="; ".join(reasons) + ". Ingestion aborted per Section 39 security mandate.",
            )

        return DocumentSecurityScanResult(
            is_safe=True,
            detected_type=header_type,
            macros_detected=[],
            embedded_programs_detected=[],
            unknown_binaries_detected=[],
            quarantine_status="clean",
            rejection_reason=None,
        )

    @classmethod
    def _identify_header(cls, data: bytes) -> Tuple[str, bool]:
        """Identifies file type from leading magic bytes and flags executable headers."""
        if data.startswith(b"%PDF-"):
            return "pdf", False
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            return "zip", False
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "ole2", False

        # Executable binary signatures
        if data.startswith(b"MZ"):  # Windows PE Executable
            return "pe_executable", True
        if data.startswith(b"\x7fELF"):  # Linux ELF Executable
            return "elf_executable", True
        if data.startswith(b"\xfe\xed\xfa\xce") or data.startswith(b"\xfe\xed\xfa\xcf") or data.startswith(b"\xca\xfe\xba\xbe"):
            return "macho_or_java_binary", True
        if data.startswith(b"#!"):  # Unix script shebang
            return "shell_script", True

        # Text formats
        sample = data[:1024].lstrip()
        lower_sample = sample.lower()
        if lower_sample.startswith(b"<!doctype html") or lower_sample.startswith(b"<html") or lower_sample.startswith(b"<xml"):
            return "html", False
        if sample.startswith(b"# ") or sample.startswith(b"## ") or b"\n# " in sample:
            return "markdown", False

        # General text vs binary
        try:
            sample.decode("utf-8")
            return "text", False
        except UnicodeDecodeError:
            return "unknown_binary", True

    @classmethod
    def _scan_pdf(cls, data: bytes, embedded: List[str], unknown: List[str]):
        """Inspects PDF streams and dictionaries for /Launch, /JavaScript, and embedded executables."""
        # Check /Launch action (executes OS programs)
        if re.search(rb"/Launch\b", data):
            embedded.append("PDF contains '/Launch' action designed to execute external programs.")

        # Check /JavaScript or /JS active scripts
        if re.search(rb"/JavaScript\b", data) or re.search(rb"/JS\s*\(", data) or re.search(rb"/JS\s*<", data):
            embedded.append("PDF contains active embedded JavaScript (/JavaScript or /JS stream).")

        # Check embedded binary files (/EmbeddedFiles)
        if re.search(rb"/EmbeddedFiles\b", data) or re.search(rb"/EF\b", data):
            # Inspect if any embedded file stream contains executable headers
            if b"MZ" in data or b"\x7fELF" in data:
                embedded.append("PDF contains embedded binary executable (MZ / ELF) inside /EmbeddedFiles.")
            else:
                embedded.append("PDF contains embedded file stream (/EmbeddedFiles).")

        # Check /OpenAction with external script execution
        if re.search(rb"/OpenAction\b", data) and (re.search(rb"/Launch\b", data) or re.search(rb"/JavaScript\b", data)):
            embedded.append("PDF triggers automated action on open (/OpenAction) invoking external execution.")

    @classmethod
    def _scan_zip_container(cls, data: bytes, macros: List[str], embedded: List[str], unknown: List[str]):
        """Inspects ZIP / OpenXML archive members for macros and embedded binaries."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.infolist():
                    name = member.filename
                    lower_name = name.lower()

                    # 1. Check macro patterns
                    for pat in cls.MACRO_FILE_PATTERNS:
                        if pat.search(name):
                            macros.append(f"Office VBA macro project file detected: '{name}'")
                            break

                    # 2. Check embedded program extensions
                    _, ext = os.path.splitext(lower_name)
                    if ext in cls.EMBEDDED_PROGRAM_EXTENSIONS:
                        embedded.append(f"Embedded executable file detected in archive: '{name}'")

                    # 3. Check OLE Object binaries
                    if "oleobject" in lower_name and lower_name.endswith(".bin"):
                        # Inspect inner content for PE header
                        try:
                            inner = zf.read(member)
                            if inner.startswith(b"MZ") or b"MZ" in inner[:512]:
                                embedded.append(f"Embedded Windows PE binary inside OLE container: '{name}'")
                            else:
                                embedded.append(f"Embedded OLE binary object container: '{name}'")
                        except Exception:
                            embedded.append(f"Embedded OLE container: '{name}'")

                    # 4. Check for nested archives exceeding safe limits
                    if ext in {".zip", ".tar", ".gz", ".7z", ".rar"}:
                        unknown.append(f"Nested archive container '{name}' prohibited inside document packages.")
        except zipfile.BadZipFile:
            unknown.append("Malformed or corrupted ZIP container structure.")

    @classmethod
    def _scan_ole2_container(cls, data: bytes, macros: List[str], embedded: List[str]):
        """Inspects legacy OLE2 compound binary files (.doc, .xls) for macros."""
        # Simple string search for legacy VBA macro streams in OLE2
        if b"_VBA_PROJECT" in data or b"VBA" in data or b"Attribut" in data:
            macros.append("Legacy OLE2 document contains active VBA macro stream.")
        if b"Package" in data and b"MZ" in data:
            embedded.append("Legacy OLE2 document contains packaged embedded PE binary.")

    @classmethod
    def _check_zip_bomb(cls, data: bytes) -> Tuple[bool, float, Optional[str]]:
        """Verifies decompression ratio and volume limits to prevent decompression bombs."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                compressed_size = len(data)
                ratio = total_uncompressed / max(compressed_size, 1)

                if ratio > cls.MAX_DECOMPRESSION_RATIO:
                    return False, ratio, f"Decompression bomb detected: ratio {ratio:.1f}:1 exceeds ceiling of {cls.MAX_DECOMPRESSION_RATIO}:1."

                if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                    return False, ratio, f"Total uncompressed volume ({total_uncompressed} bytes) exceeds {cls.MAX_UNCOMPRESSED_BYTES} bytes limit."

                return True, ratio, None
        except Exception as exc:
            return False, 1.0, f"Decompression validation error: {exc}"


class SafeDocumentParser:
    """
    Stage 3 & 4: Hardened Document Parser.
    Extracts structured text and section headings from validated documents
    without executing macros, scripts, or embedded programs.
    """

    @classmethod
    def parse(
        cls,
        file_bytes: bytes,
        detected_type: str,
        filename: str = "document.bin",
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes parser extraction returning (raw_text, section_headings, metadata_dict).
        """
        from services.documents.extractors.html_extractor import HtmlExtractor
        from services.documents.extractors.markdown_extractor import MarkdownExtractor
        from services.documents.extractors.office_extractor import OfficeExtractor
        from services.documents.extractors.pdf_extractor import PdfExtractor
        from services.documents.extractors.text_extractor import TextExtractor

        raw_text = ""
        headings: List[str] = []
        meta_dict: Dict[str, Any] = {"filename": filename, "detected_type": detected_type}

        if detected_type == "pdf":
            extractor = PdfExtractor()
            doc_meta, text, sections = extractor.extract(file_bytes, filename=filename)
            raw_text = text
            headings = [s[0] for s in sections if s[0]]
            meta_dict.update({
                "title": doc_meta.title,
                "authors": doc_meta.authors,
                "publication_date": doc_meta.publication_date,
                "page_count": doc_meta.page_count,
            })

        elif detected_type == "zip" or filename.lower().endswith((".docx", ".pptx")):
            office_ext = OfficeExtractor()
            if filename.lower().endswith(".pptx"):
                doc_meta, text, sections = office_ext.extract_pptx(file_bytes, filename=filename)
            else:
                doc_meta, text, sections = office_ext.extract_docx(file_bytes, filename=filename)
            raw_text = text
            headings = [s[0] for s in sections if s[0]]
            meta_dict.update({
                "title": doc_meta.title,
                "authors": doc_meta.authors,
                "publication_date": doc_meta.publication_date,
            })

        elif detected_type == "html" or filename.lower().endswith((".html", ".htm")):
            html_ext = HtmlExtractor()
            text_content = file_bytes.decode("utf-8", errors="replace")
            doc_meta, text, sections = html_ext.extract(text_content, source_url=filename)
            raw_text = text
            headings = [s[0] for s in sections if s[0]]
            meta_dict.update({"title": doc_meta.title})

        elif detected_type == "markdown" or filename.lower().endswith((".md", ".markdown")):
            md_ext = MarkdownExtractor()
            text_content = file_bytes.decode("utf-8", errors="replace")
            doc_meta, text, sections = md_ext.extract(text_content, source_url=filename)
            raw_text = text
            headings = [s[0] for s in sections if s[0]]
            meta_dict.update({"title": doc_meta.title})

        else:
            # Plain text fallback
            text_ext = TextExtractor()
            text_content = file_bytes.decode("utf-8", errors="replace")
            doc_meta, text, sections = text_ext.extract(text_content, source_url=filename)
            raw_text = text
            headings = [s[0] for s in sections if s[0]]
            meta_dict.update({"title": doc_meta.title})

        return raw_text, headings, meta_dict


class DocumentTextSanitizer:
    """
    Stage 5: Text Sanitization.
    Sanitizes extracted document text to prevent downstream injection vulnerabilities:
    - Strips dangerous control characters (preserving tabs and newlines)
    - Strips script tags and active HTML event handlers
    - Neutralizes spreadsheet formula injection (=CMD|, +CMD|, -CMD|, @SUM)
    - Strips null bytes and terminal escape codes
    - Normalizes Unicode representations (NFKC)
    """

    # Formula injection indicators
    FORMULA_INJECTION_PATTERN = re.compile(r"^\s*([=+@-](?:cmd|powershell|calc|bash|exec|system)\b)", re.IGNORECASE | re.MULTILINE)

    # Script tags
    SCRIPT_TAG_PATTERN = re.compile(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", re.IGNORECASE)

    # Event handlers: onload=, onclick=, onerror=, etc.
    EVENT_HANDLER_PATTERN = re.compile(r"\b(on[a-z]{3,20})\s*=", re.IGNORECASE)

    # Terminal escape codes
    ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Sanitizes extracted document text completely."""
        if not text:
            return ""

        # 1. Strip null bytes
        sanitized = text.replace("\x00", "")

        # 2. Strip ANSI terminal escape sequences
        sanitized = cls.ANSI_ESCAPE_PATTERN.sub("", sanitized)

        # 3. Strip dangerous control characters (0x01 to 0x1f except tab 0x09, newline 0x0a, cr 0x0d)
        sanitized = "".join(
            ch for ch in sanitized
            if ch in ("\t", "\n", "\r") or (ord(ch) >= 32 and ord(ch) != 127)
        )

        # 4. Strip <script>...</script> tags
        sanitized = cls.SCRIPT_TAG_PATTERN.sub("[FILTERED_SCRIPT_TAG]", sanitized)

        # 5. Neutralize active JavaScript event handlers
        sanitized = cls.EVENT_HANDLER_PATTERN.sub(r"data-disabled-event=", sanitized)

        # 6. Neutralize formula injections
        sanitized = cls.FORMULA_INJECTION_PATTERN.sub(r"' \1", sanitized)

        # 7. Normalize Unicode to NFKC
        sanitized = unicodedata.normalize("NFKC", sanitized)

        # 8. Normalize whitespace lines
        lines = [line.rstrip() for line in sanitized.splitlines()]
        return "\n".join(lines).strip()


def _isolated_worker_entrypoint(
    file_bytes: bytes,
    filename: str,
    conn: multiprocessing.connection.Connection,
):
    """
    Top-level entrypoint for isolated worker process.
    Executes stages 2 to 5 out-of-process from the main API server.
    """
    start_time = time.perf_counter()
    stages: List[PipelineStageResult] = []
    pid = os.getpid()

    try:
        # Stage 1: Worker Isolation
        worker_stage_start = time.perf_counter()
        stages.append(
            PipelineStageResult(
                stage_name="Worker",
                status="success",
                duration_ms=(time.perf_counter() - worker_stage_start) * 1000,
                details=f"Isolated worker process active (PID {pid})",
            )
        )

        # Stage 2: Sandbox Security Scanner
        scan_start = time.perf_counter()
        scan_result = DocumentSecurityScanner.scan_document(file_bytes, filename=filename)
        scan_duration = (time.perf_counter() - scan_start) * 1000

        if not scan_result.is_safe:
            stages.append(
                PipelineStageResult(
                    stage_name="Sandbox",
                    status="blocked",
                    duration_ms=scan_duration,
                    details=f"Threat blocked: {scan_result.rejection_reason}",
                )
            )
            result = SanitizedDocumentResult(
                success=False,
                filename=filename,
                detected_type=scan_result.detected_type,
                raw_text="",
                sanitized_text="",
                word_count=0,
                char_count=0,
                security_scan=scan_result,
                stages=stages,
                worker_pid=pid,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
                error=scan_result.rejection_reason,
            )
            conn.send(result)
            return

        stages.append(
            PipelineStageResult(
                stage_name="Sandbox",
                status="success",
                duration_ms=scan_duration,
                details=f"Clean format verified ({scan_result.detected_type})",
            )
        )

        # Stage 3: Parser
        parser_start = time.perf_counter()
        raw_text, headings, metadata = SafeDocumentParser.parse(
            file_bytes,
            detected_type=scan_result.detected_type,
            filename=filename,
        )
        parser_duration = (time.perf_counter() - parser_start) * 1000
        stages.append(
            PipelineStageResult(
                stage_name="Parser",
                status="success",
                duration_ms=parser_duration,
                details=f"Parsed {len(headings)} sections, {len(raw_text)} chars",
            )
        )

        # Stage 4: Extracted Text
        text_stage_start = time.perf_counter()
        word_count = len(raw_text.split())
        stages.append(
            PipelineStageResult(
                stage_name="Extracted text",
                status="success",
                duration_ms=(time.perf_counter() - text_stage_start) * 1000,
                details=f"Extracted {word_count} words",
            )
        )

        # Stage 5: Sanitized Result
        sanitize_start = time.perf_counter()
        sanitized_text = DocumentTextSanitizer.sanitize(raw_text)
        sanitize_duration = (time.perf_counter() - sanitize_start) * 1000
        stages.append(
            PipelineStageResult(
                stage_name="Sanitized result",
                status="success",
                duration_ms=sanitize_duration,
                details="Neutralized control chars, scripts, and formula injections",
            )
        )

        total_duration = (time.perf_counter() - start_time) * 1000
        result = SanitizedDocumentResult(
            success=True,
            filename=filename,
            detected_type=scan_result.detected_type,
            raw_text=raw_text,
            sanitized_text=sanitized_text,
            word_count=len(sanitized_text.split()),
            char_count=len(sanitized_text),
            headings=headings,
            metadata=metadata,
            security_scan=scan_result,
            stages=stages,
            worker_pid=pid,
            execution_time_ms=total_duration,
            error=None,
        )
        conn.send(result)

    except Exception as exc:
        total_duration = (time.perf_counter() - start_time) * 1000
        stages.append(
            PipelineStageResult(
                stage_name="Worker",
                status="failed",
                duration_ms=total_duration,
                details=f"Worker exception: {exc}",
            )
        )
        result = SanitizedDocumentResult(
            success=False,
            filename=filename,
            detected_type="error",
            raw_text="",
            sanitized_text="",
            word_count=0,
            char_count=0,
            stages=stages,
            worker_pid=pid,
            execution_time_ms=total_duration,
            error=f"Worker parsing error: {exc}",
        )
        conn.send(result)


class SandboxedDocumentProcessor:
    """
    Stage 1 - 5 Orchestrator.
    Enforces out-of-process worker execution, macro blocking, embedded program blocking,
    unknown binary blocking, and text sanitization.
    """

    def __init__(self, default_timeout: float = 15.0):
        self.default_timeout = default_timeout
        # Telemetry metrics
        self.total_processed = 0
        self.macros_blocked = 0
        self.embedded_programs_blocked = 0
        self.unknown_binaries_blocked = 0
        self.clean_documents = 0
        self.quarantined_documents = 0

    def process(
        self,
        file_bytes: Union[bytes, str],
        filename: str = "document.pdf",
        timeout: Optional[float] = None,
        enforce_worker_process: bool = True,
    ) -> SanitizedDocumentResult:
        """
        Processes an untrusted document through the complete 5-stage pipeline:
        Worker -> Sandbox -> Parser -> Extracted text -> Sanitized result.
        """
        if isinstance(file_bytes, str):
            payload = file_bytes.encode("utf-8")
        else:
            payload = file_bytes

        eff_timeout = timeout or self.default_timeout
        start_time = time.perf_counter()

        if enforce_worker_process:
            result = self._execute_in_worker(payload, filename, timeout=eff_timeout)
        else:
            result = self._execute_in_process(payload, filename)

        # Update telemetry
        self.total_processed += 1
        if result.security_scan:
            scan = result.security_scan
            if scan.macros_detected:
                self.macros_blocked += len(scan.macros_detected)
            if scan.embedded_programs_detected:
                self.embedded_programs_blocked += len(scan.embedded_programs_detected)
            if scan.unknown_binaries_detected:
                self.unknown_binaries_blocked += len(scan.unknown_binaries_detected)

            if scan.quarantine_status == "clean":
                self.clean_documents += 1
            else:
                self.quarantined_documents += 1
        elif not result.success:
            self.quarantined_documents += 1

        return result

    def _execute_in_worker(
        self,
        file_bytes: bytes,
        filename: str,
        timeout: float,
    ) -> SanitizedDocumentResult:
        """Executes parsing in an isolated worker subprocess with execution timeout."""
        parent_conn, child_conn = multiprocessing.Pipe()
        proc = multiprocessing.Process(
            target=_isolated_worker_entrypoint,
            args=(file_bytes, filename, child_conn),
            daemon=True,
        )
        proc.start()

        # Wait for worker process response within timeout
        proc.join(timeout=timeout)

        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=1.0)
            return SanitizedDocumentResult(
                success=False,
                filename=filename,
                detected_type="timeout",
                raw_text="",
                sanitized_text="",
                word_count=0,
                char_count=0,
                stages=[
                    PipelineStageResult(
                        stage_name="Worker",
                        status="failed",
                        duration_ms=timeout * 1000,
                        details=f"Worker process exceeded timeout of {timeout}s (terminated)",
                    )
                ],
                worker_pid=proc.pid,
                execution_time_ms=timeout * 1000,
                error=f"Document processing timed out after {timeout} seconds.",
            )

        if parent_conn.poll():
            res: SanitizedDocumentResult = parent_conn.recv()
            return res

        # Process exited unexpectedly without sending data
        exit_code = proc.exitcode
        return SanitizedDocumentResult(
            success=False,
            filename=filename,
            detected_type="worker_crash",
            raw_text="",
            sanitized_text="",
            word_count=0,
            char_count=0,
            stages=[
                PipelineStageResult(
                    stage_name="Worker",
                    status="failed",
                    duration_ms=0,
                    details=f"Worker process terminated unexpectedly (exit code {exit_code})",
                )
            ],
            worker_pid=proc.pid,
            execution_time_ms=0,
            error=f"Worker process terminated unexpectedly (exit code {exit_code}).",
        )

    def _execute_in_process(self, file_bytes: bytes, filename: str) -> SanitizedDocumentResult:
        """Direct in-process execution fallback with pipeline tracking."""
        parent_conn, child_conn = multiprocessing.Pipe()
        _isolated_worker_entrypoint(file_bytes, filename, child_conn)
        if parent_conn.poll():
            return parent_conn.recv()
        return SanitizedDocumentResult(
            success=False,
            filename=filename,
            detected_type="error",
            raw_text="",
            sanitized_text="",
            word_count=0,
            char_count=0,
            error="In-process execution failed to yield a result.",
        )

    def get_stats(self) -> Dict[str, Any]:
        """Returns sandbox processing metrics and neutralized threat telemetry."""
        return {
            "total_processed": self.total_processed,
            "macros_blocked": self.macros_blocked,
            "embedded_programs_blocked": self.embedded_programs_blocked,
            "unknown_binaries_blocked": self.unknown_binaries_blocked,
            "clean_documents": self.clean_documents,
            "quarantined_documents": self.quarantined_documents,
            "threat_neutralization_rate": (
                f"{((self.quarantined_documents / self.total_processed) * 100):.1f}%"
                if self.total_processed > 0 else "0.0%"
            ),
        }


# Singleton instance
sandboxed_processor = SandboxedDocumentProcessor()
