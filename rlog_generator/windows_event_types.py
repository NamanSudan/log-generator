"""Windows Event Types and their specific validation rules"""
from enum import Enum
from typing import Dict, Any

class SecurityEventID(Enum):
    """Common Windows Security Event IDs"""
    LOGON_SUCCESS = 4624
    LOGON_FAILED = 4625
    ACCOUNT_CREATED = 4720
    ACCOUNT_ENABLED = 4722
    PASSWORD_CHANGE = 4723
    ACCOUNT_LOCKED = 4740
    USER_DELETED = 4726

class SecurityLogonType(Enum):
    """Windows Security Logon Types"""
    SYSTEM = 0
    INTERACTIVE = 2
    NETWORK = 3
    BATCH = 4
    SERVICE = 5
    PROXY = 6
    UNLOCK = 7
    NETWORK_CLEAR_TEXT = 8
    NEW_CREDENTIALS = 9
    REMOTE_INTERACTIVE = 10
    CACHED_INTERACTIVE = 11

# Security Event specific templates
SECURITY_EVENT_TEMPLATES = {
    SecurityEventID.LOGON_SUCCESS: {
        "message": (
            "An account was successfully logged on.\n"
            "Subject:\n"
            "\tSecurity ID:\t\t%1\n"
            "\tAccount Name:\t\t%2\n"
            "\tAccount Domain:\t\t%3\n"
            "\tLogon ID:\t\t%4\n"
            "Logon Information:\n"
            "\tLogon Type:\t\t%5\n"
            "\tRestricted Admin Mode:\t%6\n"
            "\tVirtual Account:\t\t%7\n"
            "\tElevated Token:\t\t%8\n"
        ),
        "required_fields": [
            "SubjectUserSid",
            "SubjectUserName",
            "SubjectDomainName",
            "SubjectLogonId",
            "LogonType",
            "RestrictedAdminMode",
            "VirtualAccount",
            "ElevatedToken"
        ],
        "field_types": {
            "SubjectUserSid": "win:SID",
            "SubjectUserName": "win:UnicodeString",
            "SubjectDomainName": "win:UnicodeString",
            "SubjectLogonId": "win:HexInt64",
            "LogonType": "win:UInt32",
            "RestrictedAdminMode": "win:Boolean",
            "VirtualAccount": "win:Boolean",
            "ElevatedToken": "win:Boolean"
        }
    },
    # Add more security event templates...
}

def validate_security_event(event_id: int, data: Dict[str, Any]) -> None:
    """Validate Security Event specific fields"""
    try:
        event = SecurityEventID(event_id)
    except ValueError:
        raise ValueError(f"Unknown Security Event ID: {event_id}")

    template = SECURITY_EVENT_TEMPLATES.get(event)
    if not template:
        raise ValueError(f"No template defined for Security Event ID: {event_id}")

    # Extract field names from Data array
    if 'Data' not in data:
        raise ValueError("EventData must contain Data array")
    
    data_fields = {item['Name']: item for item in data['Data']} if data['Data'] else {}

    # Validate required fields
    missing_fields = [
        field for field in template["required_fields"]
        if field not in data_fields
    ]
    if missing_fields:
        raise ValueError(
            f"Missing required fields for Security Event {event_id}: {missing_fields}"
        )

    # Validate field types
    for field_name, field_data in data_fields.items():
        if field_name in template["field_types"]:
            expected_type = template["field_types"][field_name]
            if field_data.get('Type') != expected_type:
                raise ValueError(
                    f"Invalid type for field {field_name}. "
                    f"Expected {expected_type}, got {field_data.get('Type')}"
                )

def validate_logon_event(data: Dict[str, Any]) -> None:
    """Validate Logon Event (4624) specific fields"""
    try:
        logon_type = int(data.get("LogonType", -1))
        SecurityLogonType(logon_type)
    except ValueError:
        raise ValueError(
            f"Invalid LogonType: {logon_type}. Must be one of {[t.value for t in SecurityLogonType]}"
        )

    # Validate boolean fields
    bool_fields = ["RestrictedAdminMode", "VirtualAccount", "ElevatedToken"]
    for field in bool_fields:
        value = str(data.get(field, "")).lower()
        if value not in ("yes", "no", "true", "false", "0", "1"):
            raise ValueError(f"Invalid boolean value for {field}: {value}") 