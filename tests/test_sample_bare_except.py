"""
Test sample file with various bare except patterns for CSEC-23 testing
This file intentionally contains security issues for testing purposes
"""
import json
import os


def example_1_json_parsing():
    """Bare except with JSON operations - should suggest json.JSONDecodeError"""
    content = '{"name": "test"}'
    try:
        data = json.loads(content)
        print(data)
    except:  # CSEC-23: Should detect and suggest json.JSONDecodeError
        data = {}
    return data


def example_2_file_operations():
    """Bare except with file operations - should suggest IOError, FileNotFoundError"""
    try:
        with open('/path/to/file.txt', 'r') as f:
            content = f.read()
    except:  # CSEC-23: Should detect and suggest (IOError, FileNotFoundError)
        content = ""
    return content


def example_3_type_conversion():
    """Bare except with type conversion - should suggest ValueError, TypeError"""
    value = "123"
    try:
        number = int(value)
    except:  # CSEC-23: Should detect and suggest (ValueError, TypeError)
        number = 0
    return number


def example_4_dict_access():
    """Bare except with dictionary access - should suggest KeyError"""
    data = {"name": "test"}
    try:
        value = data["missing_key"]
    except:  # CSEC-23: Should detect and suggest KeyError
        value = None
    return value


def example_5_multiple_operations():
    """Bare except with multiple operations - should suggest based on first match"""
    try:
        content = '{"test": "data"}'
        data = json.loads(content)  # JSON operation first
        with open('file.txt', 'w') as f:  # File operation second
            f.write(str(data))
    except:  # CSEC-23: Should detect json.JSONDecodeError (first match)
        pass


def example_6_bare_except_with_pass():
    """Bare except with pass statement"""
    try:
        risky_operation()
    except: pass  # CSEC-23: Should detect


def example_7_generic_operations():
    """Bare except with no specific pattern - should suggest Exception"""
    try:
        x = 1 + 2
        y = x * 3
        result = process(y)
    except:  # CSEC-23: Should suggest Exception (generic)
        result = None
    return result


def example_8_http_requests():
    """Bare except with HTTP requests - should suggest requests.RequestException"""
    import requests
    try:
        response = requests.get('https://api.example.com/data')
        data = response.json()
    except:  # CSEC-23: Should detect and suggest requests.RequestException
        data = {}
    return data


def risky_operation():
    """Dummy function for testing"""
    pass


def process(value):
    """Dummy function for testing"""
    return value


# This file should produce 8 findings when scanned with CSEC-23 pattern
