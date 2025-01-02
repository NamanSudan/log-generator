import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import datetime
import re

from rlog_generator.validators import (
    validate_windows_event_config,
    WindowsEventValidationError,
    validate_guid,
    validate_hex_value
)
from rlog_generator.utils import get_windows_event_log
from rlog_generator.windows_event_types import SecurityEventID

class TestWindowsEventValidation(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        # Load a valid base configuration
        self.valid_config = {
            "event_descriptor": {
                "Id": 4624,
                "Version": 0,
                "Channel": 2,
                "Level": 0,
                "Opcode": 0,
                "Task": 12544,
                "Keyword": "0x8020000000000000"
            },
            "template": {
                "message": "An account was successfully logged on.\nSubject:\n\tSecurity ID:\t\t%1",
                "values": ["func_sid"]
            },
            "Event": {
                "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event",
                "System": {
                    "Provider": {
                        "Name": "Microsoft-Windows-Security-Auditing",
                        "Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"
                    },
                    "EventID": {
                        "_text": "4624",
                        "Qualifiers": "0"
                    },
                    "Version": "0",
                    "Level": "0",
                    "Task": "12544",
                    "Opcode": "0",
                    "Keywords": "0x8020000000000000",
                    "TimeCreated": {
                        "SystemTime": "func_datetime_iso8601"
                    },
                    "EventRecordID": "1234",
                    "Correlation": {
                        "ActivityID": "{12345678-1234-5678-1234-567812345678}"
                    },
                    "Execution": {
                        "ProcessID": "1234",
                        "ThreadID": "5678"
                    },
                    "Channel": "Security",
                    "Computer": "TestComputer"
                },
                "EventData": {
                    "Data": [
                        {
                            "Name": "SubjectUserSid",
                            "Type": "win:SID",
                            "_text": "func_sid"
                        },
                        {
                            "Name": "SubjectUserName",
                            "Type": "win:UnicodeString",
                            "_text": "TestUser"
                        },
                        {
                            "Name": "SubjectDomainName",
                            "Type": "win:UnicodeString",
                            "_text": "DOMAIN"
                        },
                        {
                            "Name": "SubjectLogonId",
                            "Type": "win:HexInt64",
                            "_text": "0x123456"
                        },
                        {
                            "Name": "LogonType",
                            "Type": "win:UInt32",
                            "_text": "2"
                        },
                        {
                            "Name": "RestrictedAdminMode",
                            "Type": "win:Boolean",
                            "_text": "No"
                        },
                        {
                            "Name": "VirtualAccount",
                            "Type": "win:Boolean",
                            "_text": "No"
                        },
                        {
                            "Name": "ElevatedToken",
                            "Type": "win:Boolean",
                            "_text": "Yes"
                        }
                    ]
                }
            }
        }

    def test_validate_guid(self):
        """Test GUID validation"""
        valid_guid = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
        invalid_guid = "54849625-5478-4994-A5BA-3E3B0328C30D"
        
        self.assertTrue(validate_guid(valid_guid))
        self.assertFalse(validate_guid(invalid_guid))

    def test_validate_hex_values(self):
        """Test hex value validation"""
        valid_hex32 = "0x1234ABCD"
        valid_hex64 = "0x1234567890ABCDEF"
        invalid_hex = "1234ABCD"
        
        self.assertTrue(validate_hex_value(valid_hex32, r'^0[xX][0-9A-Fa-f]{1,8}$'))
        self.assertTrue(validate_hex_value(valid_hex64, r'^0[xX][0-9A-Fa-f]{1,16}$'))
        self.assertFalse(validate_hex_value(invalid_hex, r'^0[xX][0-9A-Fa-f]{1,8}$'))

    def test_required_fields(self):
        """Test validation of required fields"""
        # Remove required field
        invalid_config = self.valid_config.copy()
        del invalid_config["Event"]["System"]["Computer"]
        
        with self.assertRaises(WindowsEventValidationError) as context:
            validate_windows_event_config(invalid_config)
        self.assertIn("Missing required System elements", str(context.exception))

    def test_numeric_types(self):
        """Test validation of numeric types"""
        invalid_config = self.valid_config.copy()
        invalid_config["Event"]["System"]["Version"] = 256
        
        with self.assertRaises(WindowsEventValidationError) as context:
            validate_windows_event_config(invalid_config)
        self.assertIn("Version must be between 0 and 255", str(context.exception))

    def test_xml_output(self):
        """Test XML output format"""
        xml_output = get_windows_event_log(self.valid_config)
        
        # Parse XML to verify structure
        root = ET.fromstring(xml_output)
        
        # Verify namespace
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        self.assertEqual(root.tag, '{http://schemas.microsoft.com/win/2004/08/events/event}Event')

    def test_event_data_types(self):
        """Test validation of EventData types"""
        config = self.valid_config.copy()
        config["Event"]["EventData"]["Data"].append({
            "Name": "TestBool",
            "Type": "win:Boolean",
            "_text": "Invalid"
        })
        
        with self.assertRaises(WindowsEventValidationError) as context:
            validate_windows_event_config(config)
        self.assertIn("Invalid boolean value", str(context.exception))

    def test_rendering_info(self):
        """Test RenderingInfo validation"""
        config = self.valid_config.copy()
        config["Event"]["RenderingInfo"] = {
            "Culture": "invalid",
            "Message": "Test message"
        }
        
        with self.assertRaises(WindowsEventValidationError) as context:
            validate_windows_event_config(config)
        self.assertIn("Invalid Culture format", str(context.exception))

    @patch('rlog_generator.utils.datetime')
    def test_datetime_format(self, mock_datetime):
        """Test datetime formatting"""
        mock_date = datetime.datetime(2024, 2, 20, 10, 0, 0)
        mock_datetime.datetime.now.return_value = mock_date
        
        xml_output = get_windows_event_log(self.valid_config)
        self.assertIn('SystemTime="2024-02-20T10:00:00"', xml_output)

if __name__ == '__main__':
    unittest.main() 