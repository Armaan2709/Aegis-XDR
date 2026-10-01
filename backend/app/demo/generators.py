"""
Synthetic Security Telemetry Generators.

Provides deterministic telemetry creation for synthetic alerts, process trees,
authentication events, network connections, file modifications, and IOCs.
All generated data is strictly synthetic and tagged with 'synthetic_telemetry'.
"""

from typing import List, Dict, Any
from app.models.alert import AlertSeverity
from app.demo.schemas import SyntheticAlertTelemetry


def generate_credential_compromise_telemetry() -> List[SyntheticAlertTelemetry]:
    """Generate deterministic synthetic telemetry for Credential Compromise scenario."""
    return [
        SyntheticAlertTelemetry(
            title="Suspicious Authentication Anomaly from External IP",
            description="Multiple failed SSH/RDP logins followed by successful login from unassigned geolocation IP 198.51.100.44 for user 'svc_backup'.",
            source="CrowdStrike Identity Threat Protection",
            source_ref_id="SYN-CRED-001",
            severity=AlertSeverity.HIGH,
            mitre_tactics=["Initial Access", "Credential Access"],
            mitre_techniques=["T1078", "T1110"],
            iocs={
                "ip_addresses": ["198.51.100.44"],
                "usernames": ["svc_backup"],
                "hosts": ["DC01.corp.internal"],
            },
            raw_payload={
                "event_type": "AUTH_ANOMALY",
                "source_ip": "198.51.100.44",
                "target_user": "svc_backup",
                "target_host": "DC01.corp.internal",
                "failed_attempts": 14,
                "login_status": "SUCCESS",
                "protocol": "Kerberos / RDP",
            },
            tags=["synthetic_telemetry", "credential_compromise", "initial_access"],
        ),
        SyntheticAlertTelemetry(
            title="LSASS Memory Dumping via Mimikatz Pattern",
            description="Process LSASS.exe accessed with PROCESS_VM_READ permissions by suspicious process powershell.exe (PID: 4892).",
            source="Microsoft Defender for Endpoint",
            source_ref_id="SYN-CRED-002",
            severity=AlertSeverity.CRITICAL,
            mitre_tactics=["Credential Access"],
            mitre_techniques=["T1003.001", "T1059.001"],
            iocs={
                "processes": ["powershell.exe", "lsass.exe"],
                "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
                "usernames": ["svc_backup"],
                "hosts": ["DC01.corp.internal"],
            },
            raw_payload={
                "event_type": "PROCESS_ACCESS",
                "source_process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
                "target_process": "C:\\Windows\\System32\\lsass.exe",
                "access_mask": "0x0010",
            },
            tags=["synthetic_telemetry", "credential_compromise", "lsass_dump"],
        ),
        SyntheticAlertTelemetry(
            title="Lateral Movement via Remote WMI Execution",
            description="WMI process wmiprvse.exe spawned cmd.exe executing psexec against internal host WS-FINANCE-04.",
            source="Suricata NIDS & Sysmon",
            source_ref_id="SYN-CRED-003",
            severity=AlertSeverity.HIGH,
            mitre_tactics=["Lateral Movement", "Execution"],
            mitre_techniques=["T1021.002", "T1047"],
            iocs={
                "ip_addresses": ["10.0.4.15", "10.0.4.88"],
                "processes": ["wmiprvse.exe", "cmd.exe", "psexec.exe"],
                "hosts": ["DC01.corp.internal", "WS-FINANCE-04.corp.internal"],
            },
            raw_payload={
                "event_type": "WMI_REMOTE_EXECUTION",
                "source_host": "DC01.corp.internal",
                "destination_host": "WS-FINANCE-04.corp.internal",
                "command_line": "cmd.exe /c psexec.exe \\\\WS-FINANCE-04 -u corp\\svc_backup -p [HASH] cmd.exe",
            },
            tags=["synthetic_telemetry", "credential_compromise", "lateral_movement"],
        ),
    ]


def generate_ransomware_telemetry() -> List[SyntheticAlertTelemetry]:
    """Generate deterministic synthetic telemetry for Ransomware Simulation scenario."""
    return [
        SyntheticAlertTelemetry(
            title="Suspicious Parent-Child Process Spawn (Cmd -> Powershell -> Vssadmin)",
            description="Execution of vssadmin.exe attempting to delete Volume Shadow Copies with quiet suppression.",
            source="CrowdStrike Falcon Sensor",
            source_ref_id="SYN-RANSOM-001",
            severity=AlertSeverity.CRITICAL,
            mitre_tactics=["Impact", "Defense Evasion"],
            mitre_techniques=["T1490", "T1059"],
            iocs={
                "processes": ["cmd.exe", "powershell.exe", "vssadmin.exe"],
                "hashes": ["7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"],
                "hosts": ["SRV-FILE-02.corp.internal"],
            },
            raw_payload={
                "event_type": "SHADOW_COPY_DELETION",
                "parent_process": "powershell.exe",
                "process_path": "C:\\Windows\\System32\\vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "user": "NT AUTHORITY\\SYSTEM",
            },
            tags=["synthetic_telemetry", "ransomware_simulation", "impact"],
        ),
        SyntheticAlertTelemetry(
            title="Mass Rapid File Extension Mutation & Encryption Burst",
            description="Over 450 files modified in 12 seconds with extension suffix '.lockbit_enc' under C:\\Shares\\Finance.",
            source="Sophos Intercept X",
            source_ref_id="SYN-RANSOM-002",
            severity=AlertSeverity.CRITICAL,
            mitre_tactics=["Impact"],
            mitre_techniques=["T1486"],
            iocs={
                "file_paths": ["C:\\Shares\\Finance\\Q3_Report.pdf.lockbit_enc"],
                "processes": ["enc_runner.exe"],
                "hashes": ["a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"],
                "hosts": ["SRV-FILE-02.corp.internal"],
            },
            raw_payload={
                "event_type": "MASS_FILE_MUTATION",
                "target_directory": "C:\\Shares\\Finance\\",
                "files_affected": 487,
                "entropy_score": 7.98,
                "encryption_extension": ".lockbit_enc",
            },
            tags=["synthetic_telemetry", "ransomware_simulation", "data_encrypted"],
        ),
        SyntheticAlertTelemetry(
            title="Windows Recovery Subsystem Disablement",
            description="Execution of bcdedit.exe modifying boot configuration parameters to disable recovery and ignore failures.",
            source="Microsoft Defender for Endpoint",
            source_ref_id="SYN-RANSOM-003",
            severity=AlertSeverity.HIGH,
            mitre_tactics=["Defense Evasion"],
            mitre_techniques=["T1490"],
            iocs={
                "processes": ["bcdedit.exe"],
                "hosts": ["SRV-FILE-02.corp.internal"],
            },
            raw_payload={
                "event_type": "BOOT_CONFIG_MODIFICATION",
                "process_path": "C:\\Windows\\System32\\bcdedit.exe",
                "command_line": "bcdedit /set {default} recoveryenabled No",
            },
            tags=["synthetic_telemetry", "ransomware_simulation", "defense_evasion"],
        ),
    ]


def generate_data_exfiltration_telemetry() -> List[SyntheticAlertTelemetry]:
    """Generate deterministic synthetic telemetry for Data Exfiltration scenario."""
    return [
        SyntheticAlertTelemetry(
            title="Large Encrypted Archive Creation in Temp Directory",
            description="7-Zip process created password-protected multi-part archive 'confidential_q4.7z' (size: 4.2 GB) in C:\\Users\\Public\\Temp.",
            source="Sysmon FileCreate Monitoring",
            source_ref_id="SYN-EXFIL-001",
            severity=AlertSeverity.HIGH,
            mitre_tactics=["Collection"],
            mitre_techniques=["T1560.001"],
            iocs={
                "processes": ["7z.exe"],
                "file_paths": ["C:\\Users\\Public\\Temp\\confidential_q4.7z"],
                "hosts": ["WS-EXEC-01.corp.internal"],
            },
            raw_payload={
                "event_type": "ARCHIVE_CREATION",
                "process": "C:\\Program Files\\7-Zip\\7z.exe",
                "command_line": "7z.exe a -p***** -mhe=on C:\\Users\\Public\\Temp\\confidential_q4.7z C:\\Data\\IP_Vault\\*",
                "archive_size_bytes": 4509715200,
            },
            tags=["synthetic_telemetry", "data_exfiltration", "collection"],
        ),
        SyntheticAlertTelemetry(
            title="High Volume Outbound HTTPS Transfer to Suspicious C2 Domain",
            description="Outbound connection burst of 4.1 GB transmitted to external domain evil-c2-exfil-node.xyz (IP: 203.0.113.195).",
            source="Palo Alto Networks Next-Gen Firewall",
            source_ref_id="SYN-EXFIL-002",
            severity=AlertSeverity.CRITICAL,
            mitre_tactics=["Command & Control", "Exfiltration"],
            mitre_techniques=["T1071.001", "T1041"],
            iocs={
                "ip_addresses": ["203.0.113.195"],
                "domains": ["evil-c2-exfil-node.xyz"],
                "hosts": ["WS-EXEC-01.corp.internal"],
            },
            raw_payload={
                "event_type": "LARGE_OUTBOUND_TRANSFER",
                "source_internal_ip": "10.0.12.105",
                "destination_external_ip": "203.0.113.195",
                "destination_domain": "evil-c2-exfil-node.xyz",
                "bytes_sent": 4410000000,
                "protocol": "HTTPS (TCP 443)",
                "tls_sni": "evil-c2-exfil-node.xyz",
            },
            tags=["synthetic_telemetry", "data_exfiltration", "c2_exfil"],
        ),
    ]
