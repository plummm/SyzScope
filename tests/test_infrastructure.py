"""Test infrastructure validation tests."""

import pytest
import sys
from pathlib import Path

# Mark this module to be excluded from coverage
# pragma: no cover


def test_python_version():
    """Test that Python version meets requirements."""
    assert sys.version_info >= (3, 8), "Python 3.8+ is required"


def test_syzscope_package_importable():
    """Test that syzscope package is importable."""
    try:
        import syzscope
        assert hasattr(syzscope, '__init__')
    except ImportError:
        pytest.fail("syzscope package should be importable")


def test_project_structure():
    """Test that expected project directories exist."""
    project_root = Path(__file__).parent.parent
    
    expected_dirs = [
        "syzscope",
        "tests",
        "tests/unit", 
        "tests/integration"
    ]
    
    for dir_name in expected_dirs:
        dir_path = project_root / dir_name
        assert dir_path.exists(), f"Directory {dir_name} should exist"
        assert dir_path.is_dir(), f"{dir_name} should be a directory"


def test_required_files_exist():
    """Test that required configuration files exist."""
    project_root = Path(__file__).parent.parent
    
    required_files = [
        "pyproject.toml",
        "requirements.txt",
        "README.md",
    ]
    
    for file_name in required_files:
        file_path = project_root / file_name
        assert file_path.exists(), f"File {file_name} should exist"
        assert file_path.is_file(), f"{file_name} should be a file"


def test_fixtures_available(temp_dir, mock_config, mock_vm_instance):
    """Test that pytest fixtures are working correctly."""
    # Test temp_dir fixture
    assert temp_dir.exists()
    assert temp_dir.is_dir()
    
    # Test mock_config fixture
    assert isinstance(mock_config, dict)
    assert "debug" in mock_config
    assert "timeout" in mock_config
    
    # Test mock_vm_instance fixture
    assert hasattr(mock_vm_instance, 'start')
    assert hasattr(mock_vm_instance, 'stop')
    assert hasattr(mock_vm_instance, 'is_running')


@pytest.mark.unit
def test_unit_test_marker():
    """Test that unit test marker works."""
    assert True


@pytest.mark.integration 
def test_integration_test_marker():
    """Test that integration test marker works."""
    assert True


@pytest.mark.slow
def test_slow_test_marker():
    """Test that slow test marker works."""
    assert True


def test_pytest_configuration():
    """Test that pytest is configured correctly."""
    # This test will only pass if pytest is running with proper configuration
    # The fact that it runs at all means pytest found the configuration
    import pytest
    
    # Check that pytest-cov is available
    try:
        import pytest_cov
    except ImportError:
        pytest.fail("pytest-cov should be available")
    
    # Check that pytest-mock is available  
    try:
        import pytest_mock
    except ImportError:
        pytest.fail("pytest-mock should be available")