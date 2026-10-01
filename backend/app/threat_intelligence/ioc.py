"""
IOC Validation & Normalization Engine.

Provides deterministic validation, type detection, and value normalization
for IPv4, IPv6, Domains, URLs, Hashes (MD5, SHA1, SHA256), Emails, Registry Keys, and Processes.
"""

import re
import ipaddress
import hashlib
from typing import Optional, Tuple
from app.threat_intelligence.models import IOCType


class IOCValidator:
    """Deterministic validation and normalization helper for IOC values."""

    # Regex patterns
    DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    URL_REGEX = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
    REGISTRY_REGEX = re.compile(r"^(HKLM|HKCU|HKU|HKCR|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\", re.IGNORECASE)

    @classmethod
    def validate_ipv4(cls, val: str) -> bool:
        """Validate IPv4 address."""
        try:
            ipaddress.IPv4Address(val.strip())
            return True
        except ValueError:
            return False

    @classmethod
    def validate_ipv6(cls, val: str) -> bool:
        """Validate IPv6 address."""
        try:
            ipaddress.IPv6Address(val.strip())
            return True
        except ValueError:
            return False

    @classmethod
    def detect_and_normalize(cls, raw_value: str, explicit_type: Optional[IOCType] = None) -> Tuple[IOCType, str]:
        """
        Detect IOC type automatically if explicit_type is not provided,
        and return normalized IOC value.
        """
        val = raw_value.strip()

        if explicit_type:
            ioc_type = explicit_type
        else:
            if cls.validate_ipv4(val):
                ioc_type = IOCType.IPV4
            elif cls.validate_ipv6(val):
                ioc_type = IOCType.IPV6
            elif cls.SHA256_REGEX.match(val):
                ioc_type = IOCType.SHA256
            elif cls.SHA1_REGEX.match(val):
                ioc_type = IOCType.SHA1
            elif cls.MD5_REGEX.match(val):
                ioc_type = IOCType.MD5
            elif cls.URL_REGEX.match(val):
                ioc_type = IOCType.URL
            elif cls.EMAIL_REGEX.match(val):
                ioc_type = IOCType.EMAIL
            elif cls.DOMAIN_REGEX.match(val):
                ioc_type = IOCType.DOMAIN
            elif cls.REGISTRY_REGEX.match(val):
                ioc_type = IOCType.REGISTRY_KEY
            elif val.endswith(".exe") or val.endswith(".dll"):
                ioc_type = IOCType.PROCESS
            else:
                ioc_type = IOCType.HOSTNAME

        # Normalization
        if ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.EMAIL, IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            normalized = val.lower()
        else:
            normalized = val

        return ioc_type, normalized

    @classmethod
    def generate_fingerprint(cls, ioc_type: IOCType, normalized_val: str) -> str:
        """Generate SHA256 fingerprint hash for unambiguous lookup."""
        raw_key = f"{ioc_type.value}:{normalized_val}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
