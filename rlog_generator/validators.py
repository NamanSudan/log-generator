"""Validation module for Windows Events"""
from typing import Dict, Any, Optional
import re

from .windows_event import EventDescriptor, WindowsEvent
from .windows_event_types import (
    SecurityEventID,
    validate_security_event,
    SECURITY_EVENT_TEMPLATES
)

# Constants for Windows Event validation
GUID_PATTERN = r'^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$'
HEX_INT32_PATTERN = r'^0[xX][0-9A-Fa-f]{1,8}$'
HEX_INT64_PATTERN = r'^0[xX][0-9A-Fa-f]{1,16}$'

# Windows Event Level definitions
WINDOWS_EVENT_LEVELS = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Informational",
    5: "Verbose"
}

# Standard Windows Event Channels
STANDARD_CHANNELS = {
    "Application": 1,
    "Security": 2,
    "System": 3,
    "Setup": 4,
    "ForwardedEvents": 5
}

class WindowsEventValidationError(Exception):
    """Custom exception for Windows Event validation errors"""
    pass

def validate_guid(guid: str) -> bool:
    """Validate GUID format"""
    return bool(re.match(GUID_PATTERN, guid))

def validate_hex_value(hex_str: str, pattern: str) -> bool:
    """Validate hex string format"""
    return bool(re.match(pattern, hex_str))

def validate_provider(provider: Dict[str, Any]) -> None:
    """Validate Provider element"""
    if not provider.get('Name') and not provider.get('Guid'):
        raise WindowsEventValidationError(
            "Provider must have either Name or Guid attribute")
    
    if provider.get('Guid') and not validate_guid(provider['Guid']):
        raise WindowsEventValidationError(
            f"Invalid Provider GUID format: {provider['Guid']}")

def validate_correlation(correlation: Dict[str, Any]) -> None:
    """Validate Correlation element"""
    if correlation.get('ActivityID') and not validate_guid(correlation['ActivityID']):
        raise WindowsEventValidationError(
            f"Invalid ActivityID GUID format: {correlation['ActivityID']}")
    
    if correlation.get('RelatedActivityID') and not validate_guid(correlation['RelatedActivityID']):
        raise WindowsEventValidationError(
            f"Invalid RelatedActivityID GUID format: {correlation['RelatedActivityID']}")

def validate_execution(execution: Dict[str, Any]) -> None:
    """Validate Execution element"""
    required = ['ProcessID', 'ThreadID']
    missing = [f for f in required if f not in execution]
    if missing:
        raise WindowsEventValidationError(
            f"Missing required Execution attributes: {', '.join(missing)}")
    
    # Validate unsigned integers
    for field in ['ProcessID', 'ThreadID', 'SessionID']:
        if field in execution:
            try:
                value = int(execution[field])
                if value < 0:
                    raise WindowsEventValidationError(
                        f"{field} must be non-negative, got {value}")
            except ValueError:
                raise WindowsEventValidationError(
                    f"Invalid {field} value: {execution[field]}")

def validate_system_properties(system: Dict[str, Any]) -> None:
    """Validate SystemProperties element"""
    # Required elements
    required = ['Provider', 'EventID', 'Computer']
    missing = [f for f in required if f not in system]
    if missing:
        raise WindowsEventValidationError(
            f"Missing required System elements: {', '.join(missing)}")

    # Validate Provider
    validate_provider(system['Provider'])

    # Validate EventID - can be either simple int or complex structure
    try:
        if isinstance(system['EventID'], dict):
            if '_text' not in system['EventID']:
                raise WindowsEventValidationError("EventID dict must have '_text' field")
            event_id = int(system['EventID']['_text'])
            # Validate Qualifiers if present
            if 'Qualifiers' in system['EventID']:
                qualifiers = int(system['EventID']['Qualifiers'])
                if qualifiers < 0:
                    raise WindowsEventValidationError(
                        f"EventID Qualifiers must be non-negative, got {qualifiers}")
        else:
            event_id = int(system['EventID'])
        
        if event_id < 0:
            raise WindowsEventValidationError(f"EventID must be non-negative, got {event_id}")
    except (ValueError, TypeError) as e:
        raise WindowsEventValidationError(f"Invalid EventID: {system['EventID']} - {str(e)}")

    # Validate optional elements
    if 'Correlation' in system:
        validate_correlation(system['Correlation'])
    
    if 'Execution' in system:
        validate_execution(system['Execution'])

    # Validate Keywords if present
    if 'Keywords' in system:
        if not validate_hex_value(system['Keywords'], HEX_INT64_PATTERN):
            raise WindowsEventValidationError(
                f"Invalid Keywords format: {system['Keywords']}")

    # Validate numeric fields
    if 'Version' in system:
        version = int(system['Version'])
        if not 0 <= version <= 255:
            raise WindowsEventValidationError(f"Version must be between 0 and 255, got {version}")

    if 'Level' in system:
        level = int(system['Level'])
        if not 0 <= level <= 15:
            raise WindowsEventValidationError(f"Level must be between 0 and 15, got {level}")

def validate_event_data(event_data: Dict[str, Any]) -> None:
    """Validate EventData element"""
    if 'Data' in event_data:
        if not isinstance(event_data['Data'], list):
            raise WindowsEventValidationError("EventData.Data must be a list")
        
        for data in event_data['Data']:
            if not isinstance(data, dict):
                raise WindowsEventValidationError("Each Data element must be a dictionary")
            if 'Name' not in data:
                raise WindowsEventValidationError("Each Data element must have a Name")
            if data.get('Type') == 'win:Boolean':
                value = str(data.get('_text', '')).lower()
                if value not in ('yes', 'no', 'true', 'false', '0', '1', 'func_bool'):
                    raise WindowsEventValidationError(
                        f"Invalid boolean value for {data['Name']}: {value}")

def validate_event_descriptor(descriptor: Dict[str, Any]) -> Optional[EventDescriptor]:
    """Validate and create EventDescriptor from dictionary"""
    try:
        # Required fields validation
        required_fields = ['Id', 'Version', 'Channel', 'Level', 'Opcode', 'Task', 'Keyword']
        missing_fields = [f for f in required_fields if f not in descriptor]
        if missing_fields:
            raise WindowsEventValidationError(
                f"Missing required fields in EventDescriptor: {', '.join(missing_fields)}")

        # Create EventDescriptor instance
        event_desc = EventDescriptor(
            Id=int(descriptor['Id']),
            Version=int(descriptor['Version']),
            Channel=int(descriptor['Channel']),
            Level=int(descriptor['Level']),
            Opcode=int(descriptor['Opcode']),
            Task=int(descriptor['Task']),
            Keyword=int(descriptor['Keyword'], 16) if isinstance(descriptor['Keyword'], str) 
                                                  else int(descriptor['Keyword'])
        )

        # Value range validation
        if not (0 <= event_desc.Level <= 15):
            raise WindowsEventValidationError(f"Level must be between 0 and 15, got {event_desc.Level}")
        
        if not (0 <= event_desc.Opcode <= 240):
            raise WindowsEventValidationError(f"Opcode must be between 0 and 240, got {event_desc.Opcode}")

        if event_desc.Task < 0:
            raise WindowsEventValidationError(f"Task must be non-negative, got {event_desc.Task}")

        return event_desc

    except (ValueError, TypeError) as e:
        raise WindowsEventValidationError(f"Invalid value in EventDescriptor: {str(e)}")

def validate_security_event_data(event_data: Dict[str, Any], event_id: int) -> None:
    """Validate Security Event specific data"""
    try:
        # Validate basic structure
        if not isinstance(event_data, dict):
            raise WindowsEventValidationError("Security Event data must be a dictionary")

        # Validate against security event schema
        validate_security_event(event_id, event_data)

    except ValueError as e:
        raise WindowsEventValidationError(f"Security Event validation failed: {str(e)}")

def validate_windows_event_config(config: Dict[str, Any]) -> None:
    """Validate complete Windows Event configuration"""
    # Required top-level fields
    required_fields = ['event_descriptor', 'template', 'Event']
    missing = [f for f in required_fields if f not in config]
    if missing:
        raise WindowsEventValidationError(f"Missing required fields: {', '.join(missing)}")

    # Validate template structure
    template = config['template']
    if not isinstance(template, dict):
        raise WindowsEventValidationError("Template must be a dictionary")
    
    if 'message' not in template or 'values' not in template:
        raise WindowsEventValidationError("Template must contain message and values")

    # Validate Event structure
    event = config['Event']
    if 'System' not in event:
        raise WindowsEventValidationError("Missing System element in Event")

    # Validate System properties
    validate_system_properties(event['System'])

    # Validate event descriptor
    validate_event_descriptor(config['event_descriptor'])

    # Additional validations...
    if 'Channel' in event['System']:
        channel_name = event['System']['Channel']
        if channel_name in STANDARD_CHANNELS:
            if config['event_descriptor']['Channel'] != STANDARD_CHANNELS[channel_name]:
                raise WindowsEventValidationError(
                    f"Channel ID mismatch for {channel_name}")

    # Event-specific validation
    event_id = config['event_descriptor']['Id']
    if event_id in [e.value for e in SecurityEventID]:
        if 'EventData' not in event:
            raise WindowsEventValidationError(
                f"Security Event {event_id} requires EventData")
        validate_security_event_data(event['EventData'], event_id)

    # Validate RenderingInfo if present
    if 'RenderingInfo' in config['Event']:
        validate_rendering_info(config['Event']['RenderingInfo'])

    # Validate EventData if present
    if 'EventData' in config['Event']:
        validate_event_data(config['Event']['EventData'])

def validate_message_format(message: str, values: list) -> None:
    """Validate message format and values"""
    # Count expected parameters in message (%1, %2, etc)
    param_count = sum(1 for i in range(1, len(values) + 2) 
                     if f"%{i}" in message)
    
    if param_count > len(values):
        raise WindowsEventValidationError(
            f"Message contains {param_count} parameters but only {len(values)} values provided")

def validate_flag(flag: int) -> None:
    """Validate Windows Event flag"""
    try:
        WindowsEventFlags(flag)
    except ValueError:
        raise WindowsEventValidationError(
            f"Invalid flag value: {flag}. Must be one of {[f.value for f in WindowsEventFlags]}") 

def validate_user_data(user_data: Dict[str, Any]) -> None:
    """Validate UserData element (custom event data)"""
    if not isinstance(user_data, dict):
        raise WindowsEventValidationError("UserData must be a dictionary")
    
    # UserData can contain any custom XML elements
    # We'll validate basic structure while allowing flexibility
    for key, value in user_data.items():
        if not isinstance(key, str):
            raise WindowsEventValidationError(f"UserData key must be string, got {type(key)}")
        if isinstance(value, dict):
            validate_user_data(value)  # Recursive validation for nested structures

def validate_debug_data(debug_data: Dict[str, Any]) -> None:
    """Validate DebugData element (WPP debug event)"""
    required = ['Component', 'Message']
    missing = [f for f in required if f not in debug_data]
    if missing:
        raise WindowsEventValidationError(
            f"Missing required DebugData elements: {', '.join(missing)}")
    
    # Validate sequence number if present
    if 'SequenceNumber' in debug_data:
        try:
            seq_num = int(debug_data['SequenceNumber'])
            if seq_num < 0:
                raise WindowsEventValidationError(
                    f"SequenceNumber must be non-negative, got {seq_num}")
        except ValueError:
            raise WindowsEventValidationError(
                f"Invalid SequenceNumber: {debug_data['SequenceNumber']}")

def validate_rendering_info(rendering: Dict[str, Any]) -> None:
    """Validate RenderingInfo element"""
    if 'Culture' not in rendering:
        raise WindowsEventValidationError("RenderingInfo must have Culture attribute")
    
    # Validate Culture format (e.g., 'en-US', 'de-DE')
    culture = rendering['Culture']
    if not re.match(r'^[a-z]{2}-[A-Z]{2}$', culture):
        raise WindowsEventValidationError(
            f"Invalid Culture format: {culture}. Expected format: 'en-US'")
    
    # Validate Keywords structure if present
    if 'Keywords' in rendering:
        keywords = rendering['Keywords']
        if not isinstance(keywords, dict) or 'Keyword' not in keywords:
            raise WindowsEventValidationError(
                "Keywords in RenderingInfo must contain Keyword elements")
        
        if not isinstance(keywords['Keyword'], list):
            raise WindowsEventValidationError("Keywords.Keyword must be a list")
        
        if len(keywords['Keyword']) > 64:
            raise WindowsEventValidationError(
                "Maximum 64 Keywords allowed in RenderingInfo")