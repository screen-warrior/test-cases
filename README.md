# EDL Server Test Cases

Comprehensive test suite for the EDL (External Dynamic List) Server pipeline functionality.

## Overview

This test suite validates the complete pipeline process including:
- HTTP data fetching from external sources
- Data validation (IPv4/IPv6 addresses)
- Data modification (filtering, transformation)
- Output formatting (CIDR notation, sorting, deduplication)

## Test Files

### `conftest.py`
Pytest configuration and shared fixtures including:
- Real Pydantic model instances (inputs, modifiers, outputs)
- HTTP response mocking utilities
- Reusable test data

### `test_pipeline_fixed.py`
Core pipeline tests (15 tests - all passing):
- Enum validation (Status, State)
- RefreshRate validation and constraints
- NewPipeline model creation and defaults
- Pipeline model with all fields
- Pipeline refresh with single/multiple inputs
- Modifier application
- HTTP error handling
- End-to-end integration workflow

### `test_validation_and_modifiers.py`
Integration tests for data flow (10 tests - 6 passing):
- Valid IPv4 address validation
- Invalid address filtering
- Whitespace and empty line handling
- IPv4Only modifier filtering
- Multi-source aggregation
- Output formatting (newline-separated, sorted)
- Real-world Palo Alto EDL aggregation scenario

### `test_pipeline_backup.py`
Backup of original tests using Mock objects (for reference only - tests will fail with Pydantic validation errors)

## Running Tests

### Install Dependencies
```bash
pip install pytest pytest-mock
```

### Run All Tests
```bash
pytest test_cases/ -v
```

### Run Specific Test File
```bash
pytest test_cases/test_pipeline_fixed.py -v
pytest test_cases/test_validation_and_modifiers.py -v
```

### Run Specific Test Class
```bash
pytest test_cases/test_pipeline_fixed.py::TestEnums -v
```

### Run Specific Test
```bash
pytest test_cases/test_pipeline_fixed.py::TestEnums::test_status_enum_values -v
```

## Test Approach

### Real Models + Mocked HTTP Layer
This test suite uses the **correct approach** for testing Pydantic models:

```python
# ✅ CORRECT: Real Pydantic models with mocked HTTP
real_input = ExternalEdl(type="edl", url="https://test.com/edl")
real_output = IPv4Only(type="ipv4")

with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
    mock_get.return_value = mock_http_response()

    pipeline = Pipeline(
        ...,
        inputs=[real_input],
        outputs=[real_output]
    )

    result = pipeline.refresh()
```

### Why Not Mock Objects?
```python
# ❌ WRONG: Mock objects fail Pydantic validation
mock_input = Mock()
mock_input.type = "edl"

# This will raise ValidationError:
# "Input should be a valid dictionary or instance of ExternalEdl"
pipeline = Pipeline(..., inputs=[mock_input])
```

## Key Findings

### ✅ Working Features
- Valid IPv4 addresses pass validation
- Invalid addresses are filtered correctly
- IPv4Only modifier filters IPv6 addresses
- Multi-source aggregation works
- Output is newline-separated and sorted
- IPs formatted in CIDR notation (192.168.1.1/32) - **expected behavior**

### ⚠️ Known Issues (Revealed by Tests)
1. **Deduplication not implemented** - Duplicate IPs from multiple sources appear multiple times
2. **Whitespace handling** - Leading spaces cause IPs to be rejected
3. **IPv6 filtering** - IPv6 addresses filtered even without modifiers

## Test Coverage

- **Enum validation**: Status, State enums
- **Model validation**: RefreshRate, NewPipeline, Pipeline
- **Data validation**: IPv4/IPv6 address parsing
- **Modifiers**: IPv4Only filtering
- **Outputs**: IPv4Only, IPv6Only, All types
- **Integration**: Complete pipeline workflow
- **Error handling**: HTTP errors, invalid data

## Dependencies

The test suite requires the following from the parent project:
- `fwdev_edl_server.models.pipeline`
- `fwdev_edl_server.models.inputs`
- `fwdev_edl_server.models.outputs`
- `fwdev_edl_server.models.modifiers`

## Notes

- All tests use UTC timezone for datetime operations
- HTTP layer is mocked to avoid external dependencies
- Tests validate actual Pydantic validation behavior
- CIDR notation (/32 suffix) is intentional and expected
