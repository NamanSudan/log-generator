from enum import Enum

class EventGeneratorType(Enum):
    TEMPLATE = "template"
    RAW = "raw"
    WINDOWS_EVENT = "windows_event"

class WindowsEventFlags(Enum):
    """Windows Event Message Format Flags"""
    EvtFormatMessageEvent = 0x00000001
    EvtFormatMessageLevel = 0x00000002
    EvtFormatMessageTask = 0x00000003
    EvtFormatMessageOpcode = 0x00000004
    EvtFormatMessageKeyword = 0x00000005
    EvtFormatMessageChannel = 0x00000006
    EvtFormatMessageProvider = 0x00000007
    EvtFormatMessageId = 0x00000008 