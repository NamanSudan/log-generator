# -*- coding: utf-8 -*-

"""
Copyright 2019 Würth Phoenix S.r.l.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""Utils module for rlog_generator."""


import datetime
import logging
import random
import socket
import struct
import sys
import uuid
from typing import List, Dict, Any

import yaml
from .windows_event import EventDescriptor
from .validators import (
    validate_windows_event_config, 
    validate_message_format,
    WindowsEventValidationError
)


log = logging.getLogger(__name__)


def load_config(yaml_file):
    """Return a Python object given a YAML file

    Arguments:
        yaml_file {str} -- path of YAML file

    Returns:
        obj -- Python object of YAML file
    """
    with open(yaml_file, 'r') as f:
        log.debug(f"Loading file {yaml_file}")
        return yaml.load(f, Loader=yaml.FullLoader)


def randint(min_value, max_value):
    """Return random integer in range [min_value, max_value],
    including both end points

    Arguments:
        min_value {int} -- min value
        max_value {int} -- max value

    Returns:
        int -- random integer in range [min_value, max_value]
    """
    return random.randint(int(min_value), int(max_value))


def randip():
    """Return random IP address

    Returns:
        str -- IP address
    """
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))


def get_function(function_str, module=sys.modules[__name__]):
    """Return the function from its string name as func_name"""
    # Check if it's a function call (starts with func_)
    if not function_str.startswith('func_'):
        return lambda: function_str  # Return the value as-is if not a function
    
    function_str = function_str.split("_")[1]
    try:
        return getattr(module, f"func_{function_str}")
    except AttributeError:
        raise ValueError(f"Unknown function: func_{function_str}")


def exec_function_str(function_str):
    """Return the value of all string function with/without
    parameters.
    Example: a complete string 'func_randint 1 10' runs the function
    randint(1, 10)

    Arguments:
        function_str {str} -- complete string function

    Returns:
        any -- value of string function
    """
    tokens = function_str.split()
    func = get_function(tokens[0])
    if len(tokens) == 1:
        return func()
    else:
        return func(*tokens[1:])


def get_random_value(field_value: str) -> str:
    """Get random value based on field configuration"""
    if not isinstance(field_value, str):
        return str(field_value)
    
    try:
        return exec_function_str(field_value)
    except (ValueError, IndexError) as e:
        log.warning(f"Failed to execute function for {field_value}: {str(e)}")
        return field_value  # Return original value if not a function


def get_template_log(template, fields):
    """Return a random log from template string in Python formatting string
    (https://docs.python.org/3/library/string.html#custom-string-formatting)

    Arguments:
        template {str} -- template string in Python formatting string
        fields {[type]} -- dict field from pattern configuration file

    Returns:
        str -- random log generated from template
    """
    values = {k: get_random_value(v) for k, v in fields.items()}
    now = datetime.datetime.now()
    return template.format(now, **values)


def custom_log(level="WARNING", name=None):  # pragma: no cover
    if name:
        log = logging.getLogger(name)
    else:
        log = logging.getLogger()
    log.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(name)s | "
        "%(module)s | "
        "%(funcName)s | "
        "%(levelname)s | "
        "%(message)s")
    ch.setFormatter(formatter)
    log.addHandler(ch)
    return log


def func_guid():
    """Generate random GUID in Windows format"""
    return "{" + str(uuid.uuid4()) + "}"


def func_sid():
    """Generate random Windows SID"""
    return f"S-1-5-21-{random.randint(1000000000,9999999999)}"


def func_hostname():
    """Generate random hostname"""
    return f"WIN-{random.randint(1000,9999)}"


def func_datetime():
    """Generate datetime in Windows Event format"""
    return datetime.datetime.now().isoformat()


def validate_event_descriptor(event: EventDescriptor) -> bool:
    """Validate Event Descriptor according to Windows specs"""
    return (
        0 <= event.Level <= 15 and
        0 <= event.Opcode <= 240 and
        event.Task >= 0
    )


def format_windows_message(message: str, values: List[str]) -> str:
    """Format Windows Event message with parameter substitution"""
    for i, value in enumerate(values, 1):
        message = message.replace(f"%{i}", value)
    return message


def get_windows_event_log(config: Dict[str, Any]) -> str:
    """Generate Windows Event log with validation"""
    try:
        # Validate entire configuration
        validate_windows_event_config(config)
        
        # Build XML structure
        xml = ['<?xml version="1.0" encoding="UTF-8"?>']
        
        # Add Event with namespace
        xml.append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">')
        
        # Add System section
        xml.append('  <System>')
        system = config['Event']['System']
        for key, value in system.items():
            if isinstance(value, dict):
                # Handle attributes
                attrs = []
                text = ""
                for k, v in value.items():
                    if k == '_text':
                        text = get_random_value(v)
                    else:
                        attrs.append(f'{k}="{get_random_value(v)}"')
                
                if attrs:
                    xml.append(f'    <{key} {" ".join(attrs)}>{text}</{key}>')
                else:
                    xml.append(f'    <{key}>{text}</{key}>')
            else:
                xml.append(f'    <{key}>{get_random_value(value)}</{key}>')
        xml.append('  </System>')
        
        # Add EventData section if present
        if 'EventData' in config['Event']:
            xml.append('  <EventData>')
            for data in config['Event']['EventData']['Data']:
                attrs = []
                text = ""
                for k, v in data.items():
                    if k == '_text':
                        text = get_random_value(v)
                    else:
                        attrs.append(f'{k}="{v}"')
                
                if attrs:
                    xml.append(f'    <Data {" ".join(attrs)}>{text}</Data>')
                else:
                    xml.append(f'    <Data>{text}</Data>')
            xml.append('  </EventData>')
        
        xml.append('</Event>')
        return '\n'.join(xml)
        
    except WindowsEventValidationError as e:
        log.error(f"Windows Event validation error: {str(e)}")
        raise
    except Exception as e:
        log.error(f"Unexpected error generating Windows Event: {str(e)}")
        raise


def func_datetime_iso8601():
    """Generate ISO8601 formatted datetime"""
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
