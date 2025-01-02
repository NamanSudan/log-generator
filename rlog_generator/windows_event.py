"""Windows Event data structures"""
from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class EventDescriptor:
    """Windows Event Descriptor structure as per MS-DTYP 2.3.1"""
    Id: int  # USHORT
    Version: int  # UCHAR
    Channel: int  # UCHAR
    Level: int  # UCHAR
    Opcode: int  # UCHAR
    Task: int  # USHORT
    Keyword: int  # ULONGLONG

@dataclass
class WindowsEvent:
    """Core Windows Event structure"""
    System: Dict  # SystemPropertiesType
    EventData: Optional[Dict] = None  # EventDataType
    UserData: Optional[Dict] = None  # UserDataType
    DebugData: Optional[Dict] = None  # DebugDataType
    RenderingInfo: Optional[Dict] = None  # RenderingInfoType