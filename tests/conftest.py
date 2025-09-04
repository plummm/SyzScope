"""Shared pytest fixtures for syzscope testing."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator
from unittest.mock import Mock, MagicMock

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    try:
        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir: Path) -> Generator[Path, None, None]:
    """Provide a temporary file for testing."""
    temp_file = temp_dir / "test_file.txt"
    temp_file.touch()
    yield temp_file


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Provide mock configuration for testing."""
    return {
        "debug": True,
        "timeout": 30,
        "max_retries": 3,
        "log_level": "INFO",
        "work_dir": "/tmp/syzscope_test",
        "vm_config": {
            "memory": "2G",
            "cpu_count": 2,
            "disk_size": "10G",
        },
        "analysis_config": {
            "max_depth": 100,
            "enable_caching": True,
            "timeout": 300,
        }
    }


@pytest.fixture
def mock_vm_instance():
    """Mock VM instance for testing."""
    vm_mock = Mock()
    vm_mock.start.return_value = True
    vm_mock.stop.return_value = True
    vm_mock.is_running.return_value = True
    vm_mock.execute_command.return_value = ("output", "", 0)
    vm_mock.upload_file.return_value = True
    vm_mock.download_file.return_value = True
    return vm_mock


@pytest.fixture
def mock_kernel():
    """Mock kernel for testing."""
    kernel_mock = Mock()
    kernel_mock.version = "5.4.0"
    kernel_mock.arch = "x86_64"
    kernel_mock.config = {"CONFIG_KASAN": True, "CONFIG_KCOV": True}
    kernel_mock.build.return_value = True
    kernel_mock.get_symbols.return_value = {"func1": 0x12345, "func2": 0x67890}
    return kernel_mock


@pytest.fixture
def mock_crash_case():
    """Mock crash case for testing."""
    crash_mock = Mock()
    crash_mock.title = "Test crash case"
    crash_mock.reproducer = "test_reproducer.c"
    crash_mock.syzkaller_prog = "test_prog"
    crash_mock.kernel_config = "test_config"
    crash_mock.crash_log = "test crash log"
    crash_mock.manager = "test_manager"
    crash_mock.time = "2023-01-01 12:00:00"
    return crash_mock


@pytest.fixture
def mock_static_analyzer():
    """Mock static analyzer for testing."""
    analyzer_mock = Mock()
    analyzer_mock.analyze.return_value = {
        "vulnerabilities": [],
        "call_graph": {},
        "data_flow": {},
        "taint_analysis": {}
    }
    analyzer_mock.get_function_info.return_value = {
        "name": "test_func",
        "file": "test.c",
        "line": 100,
        "type": "function"
    }
    return analyzer_mock


@pytest.fixture
def mock_symbolic_executor():
    """Mock symbolic executor for testing."""
    sym_exec_mock = Mock()
    sym_exec_mock.run.return_value = {
        "states": [],
        "constraints": [],
        "memory_map": {},
        "registers": {}
    }
    sym_exec_mock.add_constraint.return_value = True
    sym_exec_mock.solve.return_value = {"solution": True, "model": {}}
    return sym_exec_mock


@pytest.fixture
def mock_gdb_session():
    """Mock GDB session for testing."""
    gdb_mock = Mock()
    gdb_mock.attach.return_value = True
    gdb_mock.detach.return_value = True
    gdb_mock.set_breakpoint.return_value = 1
    gdb_mock.continue_execution.return_value = True
    gdb_mock.get_registers.return_value = {"rax": 0x123, "rbx": 0x456}
    gdb_mock.get_memory.return_value = b"\x00\x01\x02\x03"
    gdb_mock.execute_command.return_value = "gdb output"
    return gdb_mock


@pytest.fixture
def sample_binary_path(temp_dir: Path) -> Path:
    """Provide path to a sample binary for testing."""
    binary_path = temp_dir / "sample_binary"
    # Create a minimal ELF file header for testing
    with open(binary_path, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)  # Minimal ELF header
    return binary_path


@pytest.fixture
def sample_c_file(temp_dir: Path) -> Path:
    """Provide a sample C file for testing."""
    c_file = temp_dir / "sample.c"
    c_file.write_text("""
#include <stdio.h>
#include <stdlib.h>

int vulnerable_function(char *input) {
    char buffer[128];
    strcpy(buffer, input);  // Potential buffer overflow
    return strlen(buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        return vulnerable_function(argv[1]);
    }
    return 0;
}
""")
    return c_file


@pytest.fixture
def mock_environment_vars(monkeypatch):
    """Mock environment variables for testing."""
    test_env = {
        "SYZSCOPE_DEBUG": "1",
        "SYZSCOPE_WORKDIR": "/tmp/syzscope_test",
        "SYZSCOPE_TIMEOUT": "300",
        "QEMU_PATH": "/usr/bin/qemu-system-x86_64",
    }
    for key, value in test_env.items():
        monkeypatch.setenv(key, value)
    return test_env


@pytest.fixture
def mock_file_system(monkeypatch, temp_dir: Path):
    """Mock file system operations for testing."""
    def mock_exists(path):
        return True if "existing" in str(path) else False
    
    def mock_isfile(path):
        return True if "file" in str(path) else False
    
    def mock_isdir(path):
        return True if "dir" in str(path) else False
    
    monkeypatch.setattr(os.path, "exists", mock_exists)
    monkeypatch.setattr(os.path, "isfile", mock_isfile)
    monkeypatch.setattr(os.path, "isdir", mock_isdir)


@pytest.fixture
def capture_logs(caplog):
    """Fixture to capture and provide access to logs."""
    return caplog


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Provide path to test data directory."""
    return Path(__file__).parent / "data"


# Pytest configuration and custom markers
pytest_plugins = ["pytest_mock"]