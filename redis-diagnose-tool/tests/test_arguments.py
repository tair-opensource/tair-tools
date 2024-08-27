from diagnose.arguments import *

from unittest import mock
import pytest

TEST_DIR = os.path.dirname(__file__)


# Mocking the logger to prevent actual logging during tests
@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("diagnose.arguments.logger") as logger:
        yield logger


def test_parse_cmd_args_default_values():
    sys.argv = [
        "",
        "-h", "hostname"
    ]
    args = parse_cmd_args()
    assert args.config is None
    assert not args.advanced
    assert not args.detect_server
    assert args.language == "zh"
    assert args.host == "hostname"
    assert args.port == 6379
    assert args.timeout == 2
    assert args.user is None
    assert args.password is None
    assert args.redis is None
    assert args.redis_region_id is None
    assert args.redis_endpoint is None
    assert args.ecs is None
    assert args.ecs_region_id is None
    assert args.ecs_endpoint is None
    assert args.ak is None
    assert args.sk is None


def test_parse_cmd_args_with_arguments():
    sys.argv = [
        "",
        "-c", "path/to/config",
        "-A",
        "-d",
        "-l", "en",
        "-h", "127.0.0.1",
        "-p", "6380",
        "-t", "5",
        "-a", "password",
        "-r", "redis_instance",
        "-g", "redis_region",
        "-o", "redis_endpoint",
        "-e", "ecs_instance",
        "-G", "ecs_region",
        "-O", "ecs_endpoint",
        "-k", "ak",
        "-s", "sk"
    ]
    args = parse_cmd_args()
    assert args.config == "path/to/config"
    assert args.advanced
    assert args.detect_server
    assert args.language == "en"
    assert args.host == "127.0.0.1"
    assert args.port == 6380
    assert args.timeout == 5
    assert args.user is None
    assert args.password == "password"
    assert args.redis == "redis_instance"
    assert args.redis_region_id == "redis_region"
    assert args.redis_endpoint == "redis_endpoint"
    assert args.ecs == "ecs_instance"
    assert args.ecs_region_id == "ecs_region"
    assert args.ecs_endpoint == "ecs_endpoint"
    assert args.ak == "ak"
    assert args.sk == "sk"


@pytest.fixture
def valid_config_path():
    valid_config_content = """
    address: example.com
    user: \"\"
    password: password
    redis: redis_instance_id
    redis_region_id: region1
    redis_endpoint: endpoint1
    ecs: ecs_instance_id
    ecs_region_id: region2
    ecs_endpoint: endpoint2
    """
    config_path = os.path.join(TEST_DIR, "valid_config.yaml")
    try:
        with open(config_path, "w") as f:
            f.write(valid_config_content)
        yield config_path
    except Exception:
        pass
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


@pytest.fixture
def nonexistent_config_path():
    return os.path.join(TEST_DIR, "nonexistent_config.yaml")


@pytest.fixture
def invalid_config_path():
    config_path = os.path.join(TEST_DIR, "invalid_config.txt")
    try:
        with open(config_path, "w") as f:
            pass
        yield config_path
    except Exception:
        pass
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


def test_load_config_with_valid_file(valid_config_path):
    config = load_config(valid_config_path)
    assert config is not None
    assert isinstance(config, dict)

    # Test default value
    assert config["language"] == "zh"
    assert not config["advanced"]
    assert not config["detect_server"]
    assert config["port"] == 6379
    assert config["timeout"] == 2

    # Test specified value
    assert config["address"] == "example.com"
    assert config["user"] is None
    assert config["password"] == "password"
    assert "ak" in config.keys()
    assert "sk" in config.keys()


def test_load_config_with_invalid_path(nonexistent_config_path):
    config = load_config(nonexistent_config_path)
    assert config is None


def test_load_config_with_invalid_extension(invalid_config_path):
    config = load_config(invalid_config_path)
    assert config is None


# Test cases for validate_args function
@pytest.mark.parametrize("args, expected", [
    # Test case for valid arguments with advanced mode enabled
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=10,
                redis="redis-instance-id",
                ak="access-key-id",
                sk="access-key-secret",
                redis_region_id="redis-region-id",
                redis_endpoint="redis-endpoint",
                ecs=None,
                ecs_region_id=None,
                ecs_endpoint=None,
                advanced=True
            ),
            True
    ),
    # Test case for invalid redis with advanced mode enabled
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=10,
                redis=None,
                ak="access-key-id",
                sk="access-key-secret",
                redis_region_id="redis-region-id",
                redis_endpoint="redis-endpoint",
                ecs=None,
                ecs_region_id=None,
                ecs_endpoint=None,
                advanced=True
            ),
            False
    ),
    # Test case for invalid ak with advanced mode enabled
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=10,
                redis="redis",
                ak=None,
                sk="access-key-secret",
                redis_region_id="redis-region-id",
                redis_endpoint="redis-endpoint",
                ecs=None,
                ecs_region_id=None,
                ecs_endpoint=None,
                advanced=True
            ),
            False
    ),
    # Test case for invalid redis region and endpoint with advanced mode enabled
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=10,
                redis="redis",
                ak="access-key-id",
                sk="access-key-secret",
                redis_region_id=None,
                redis_endpoint=None,
                ecs=None,
                ecs_region_id=None,
                ecs_endpoint=None,
                advanced=True
            ),
            False
    ),
    # Test case for invalid ecs region and endpoint with advanced mode enabled
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=10,
                redis="redis",
                ak="access-key-id",
                sk="access-key-secret",
                redis_region_id="redis-region-id",
                redis_endpoint="redis-endpoint",
                ecs="ecs",
                ecs_region_id=None,
                ecs_endpoint=None,
                advanced=True
            ),
            False
    ),
    # Test case for missing address
    (
            argparse.Namespace(
                host=None,
                language="en",
                port=6379,
                timeout=10,
            ),
            False
    ),
    # Test case for wrong port
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=0,
                timeout=10,
            ),
            False
    ),
    # Test case for wrong timeout
    (
            argparse.Namespace(
                host="hostname",
                language="en",
                port=6379,
                timeout=0,
            ),
            False
    ),
    # Test case for unsupported language
    (
            argparse.Namespace(
                host="hostname",
                language="language",
                port=6379,
                timeout=10,
            ),
            False
    ),
])
def test_validate_args(args, expected):
    result = validate_args(args)
    assert result == expected
