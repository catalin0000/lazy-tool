import os
import pytest

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), 'sample_outputs')


@pytest.fixture
def sample_dir():
    return SAMPLE_DIR


@pytest.fixture
def single_host_path():
    return os.path.join(SAMPLE_DIR, 'single_host.xml')


@pytest.fixture
def multi_host_path():
    return os.path.join(SAMPLE_DIR, 'multi_host.xml')


@pytest.fixture
def no_open_ports_path():
    return os.path.join(SAMPLE_DIR, 'no_open_ports.xml')


@pytest.fixture
def no_live_hosts_path():
    return os.path.join(SAMPLE_DIR, 'no_live_hosts.xml')


@pytest.fixture
def ssl_wrapped_path():
    return os.path.join(SAMPLE_DIR, 'ssl_wrapped.xml')


@pytest.fixture
def empty_path():
    return os.path.join(SAMPLE_DIR, 'empty.xml')


@pytest.fixture
def extra_services_path():
    return os.path.join(SAMPLE_DIR, 'extra_services.xml')
