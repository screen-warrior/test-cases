# Test Suite Documentation

Comprehensive test coverage for the fwdev_internal_server core components.

## Test Files Overview

| File | Tests | Lines | Focus Area |
|------|-------|-------|------------|
| `test_validators.py` | ~40 | ~450 | Data validation (IPs, FQDNs, URLs) |
| `test_modifiers.py` | ~50 | ~650 | Subnet filtering logic |
| `test_outputs.py` | ~45 | ~550 | Output formatting |
| `test_pipeline_models.py` | ~55 | ~650 | Model validation |
| `test_pipeline_core.py` | ~25 | ~600 | Pipeline refresh integration |
| **TOTAL** | **~215** | **~2,900** | **Core components** |

---

## Running Tests

### Run All Tests
```bash
pytest test_cases/ -v
```

### Run Specific Test File
```bash
pytest test_cases/test_validators.py -v
pytest test_cases/test_modifiers.py -v
```

### Run with Coverage
```bash
pytest test_cases/ --cov=fwdev_edl_server --cov-report=html
```

---

## Test Approach

**Real Models + Mocked HTTP**
- ✅ Uses real Pydantic models (tests actual validation)
- ✅ Mocks only external dependencies (HTTP requests)
- ❌ Never uses Mock objects for models (bypasses Pydantic)

---

## What's Tested

### ✅ Core Components
1. Data validation (IPs, FQDNs, URLs)
2. Subnet filtering (IPv4/IPv6, permit/deny)
3. Output formatting (sorting, CIDR notation)
4. Model validation (RefreshRate, Pipeline)
5. Pipeline refresh workflow (integration)

### ❌ Not Tested (v1)
1. HTTP requests (mocked)
2. Database operations (requires separate setup)
3. API endpoints (requires FastAPI TestClient)
4. Background tasks (requires Huey setup)

---

## Test Quality: 215 comprehensive tests covering all core business logic
