"""
Case Management Attachment Metadata Submodule Logic.

Validates attachment metadata (reports, pcap, memory dumps, screenshots, logs, IOCs).
Enforces metadata integrity rules. Storage metadata only - no file storage implementation.
"""

import re
from app.case_management.models import AttachmentType
from app.core.exceptions import ValidationError


class AttachmentValidator:
    """Metadata validation engine for forensic case attachments."""

    SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

    @classmethod
    def validate_metadata(
        cls,
        filename: str,
        file_size_bytes: int,
        file_hash: str,
        attachment_type: AttachmentType,
    ) -> None:
        """Validate attachment file metadata structure."""
        if not filename or len(filename.strip()) == 0:
            raise ValidationError("Filename cannot be empty")

        if file_size_bytes < 0:
            raise ValidationError("File size bytes cannot be negative")

        if not cls.SHA256_REGEX.match(file_hash):
            raise ValidationError("File hash must be a valid 64-character hex SHA-256 string")

        if not isinstance(attachment_type, AttachmentType):
            raise ValidationError(f"Invalid attachment classification type: {attachment_type}")

    @staticmethod
    def generate_storage_uri_placeholder(case_number: str, filename: str) -> str:
        """Generate metadata storage URI pointer placeholder."""
        clean_filename = filename.replace(" ", "_")
        return f"s3://aegis-xdr-case-artifacts/{case_number}/{clean_filename}"
