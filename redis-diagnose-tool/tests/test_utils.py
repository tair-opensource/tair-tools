import socket
import requests

from diagnose import utils
from diagnose.exceptions import InternalError

import pytest
from unittest.mock import patch, mock_open
from unittest.mock import MagicMock


def test_get_system_info():
    # Test Windows
    with patch("diagnose.utils.platform") as mock_platform:
        mock_platform.system.return_value = "Windows"
        mock_platform.release.return_value = "10.0.19041.1"
        mock_platform.version.return_value = "10"
        expected = ("Windows", "Windows - 10.0.19041.1 - (Version 10)")
        assert utils.get_system_info() == expected

    # Test MacOs
    with patch("diagnose.utils.platform") as mock_platform:
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "19.6.0"
        mock_platform.mac_ver.return_value = ("10.15.7",)
        expected = ("MacOS", "MacOS - 19.6.0 - (Version 10.15.7)")
        assert utils.get_system_info() == expected

    # Test Linux
    with patch("diagnose.utils.platform") as mock_platform:
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.0-83-generic"
        mock_platform.version.return_value = "20.04"
        with patch("diagnose.utils.distro") as mock_distro:
            mock_distro.name.return_value = "Ubuntu"
            mock_distro.version.return_value = "20.04"
            expected = ("Linux", "Ubuntu - 5.15.0-83-generic - (Version 20.04)")
            assert utils.get_system_info() == expected


def test_is_valid_ip():
    assert utils.is_valid_ip("192.168.1.1")
    assert utils.is_valid_ip("2001:db8::")
    assert utils.is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    assert not utils.is_valid_ip("192.168.1.256")
    assert not utils.is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:733G")
    assert not utils.is_valid_ip("")


def test_check_ip_address_type():
    assert utils.get_ip_address_type("192.168.0.1") == "IPv4"
    assert utils.get_ip_address_type("2001:db8::") == "IPv6"

    # Invalid ip
    assert utils.get_ip_address_type("192.168.0.256") == "Error"
    assert utils.get_ip_address_type("::G") == "Error"
    assert utils.get_ip_address_type("192.168.1.1/24") == "Error"
    assert utils.get_ip_address_type("2001:db8::/32") == "Error"


def test_is_ip_in_cidr():
    # IPV4
    assert utils.is_ip_in_cidr("192.168.0.1", "192.168.0.0/24")
    assert utils.is_ip_in_cidr("192.168.0.1", "192.168.0.1")
    assert not utils.is_ip_in_cidr("192.168.2.1", "192.168.1.0/24")
    assert not utils.is_ip_in_cidr("192.168.2.1", "192.168.1.0")

    # IPV6
    assert utils.is_ip_in_cidr("2001:db8::1", "2001:db8::/32")
    assert utils.is_ip_in_cidr("2001:db8::1", "2001:db8::1")
    assert not utils.is_ip_in_cidr("2001:ab8:1234::1", "2001:db8::/24")
    assert not utils.is_ip_in_cidr("2001:db8:1234::1", "2001:db8::1")

    # Invalid ip
    with pytest.raises(InternalError):
        utils.is_ip_in_cidr("192.168.0.1", "192.168.0.0/33")
    with pytest.raises(InternalError):
        utils.is_ip_in_cidr("192.168.0.256", "192.168.0.0/24")
    with pytest.raises(InternalError):
        utils.is_ip_in_cidr("2001:db8:::1", "2001:db8::/32")


def test_get_ipv4_interfaces():
    def MockAddress(family, address):
        mock_addr = MagicMock()
        mock_addr.family = family
        mock_addr.address = address
        return mock_addr

    mock_net_if_addrs = {
        "eth0": [
            MockAddress(family=socket.AF_INET, address="192.168.1.1"),
            MockAddress(family=socket.AF_INET6, address="::1"),
        ],
        "lo": [
            MockAddress(family=socket.AF_INET, address="127.0.0.1"),
        ],
        "eth1": [
            MockAddress(family=socket.AF_INET, address="192.168.1.100"),
        ]
    }

    with patch("diagnose.utils.psutil.net_if_addrs", return_value=mock_net_if_addrs):
        ipv4_interfaces = utils.get_ipv4_interfaces()
        expected_result = [
            {"interface": "eth0", "ip_address": "192.168.1.1"},
            {"interface": "eth1", "ip_address": "192.168.1.100"}
        ]
        assert ipv4_interfaces == expected_result


def test_get_public_ip_address():
    with patch("diagnose.utils.requests.get") as mock_requests_get:
        mock_response = mock_requests_get.return_value

        # Successfully get IPv4
        mock_response.status_code = 200
        mock_response.text = "8.8.8.8"
        ip_address = utils.get_public_ip_address()
        assert ip_address == "8.8.8.8"

        # Successfully get IPv6
        mock_response.status_code = 200
        mock_response.text = "2001:4860:4860::8888"
        ip_address = utils.get_public_ip_address()
        assert ip_address == "2001:4860:4860::8888"

        # Invalid ip
        mock_response.status_code = 200
        mock_response.text = "8.8.8."
        ip_address = utils.get_public_ip_address()
        assert ip_address is None

        # Error
        mock_requests_get.side_effect = requests.RequestException("Connection error")
        ip_address = utils.get_public_ip_address()
        assert ip_address is None

        # Invalid url
        mock_response.status_code = 404
        ip_address = utils.get_public_ip_address()
        assert ip_address is None


def test_read_resolv_conf():
    # Test read_resolve_config with a single nameserver
    with patch("builtins.open", new_callable=mock_open, read_data="nameserver 8.8.8.8\n"):
        expected = ["8.8.8.8"]
        assert utils.read_resolve_config() == expected

    # Test read_resolve_config with multiple nameservers
    with patch("builtins.open", new_callable=mock_open, read_data="nameserver 8.8.8.8\nnameserver 8.8.4.4\n"):
        expected = ["8.8.8.8", "8.8.4.4"]
        assert utils.read_resolve_config() == expected

    # Test read_resolve_config with no nameserver in the file
    with patch("builtins.open", new_callable=mock_open, read_data="search example.com\n"):
        expected = []
        assert utils.read_resolve_config() == expected

    # Test read_resolve_config when the file is not found
    with patch("builtins.open", mock_open()) as m:
        m.side_effect = FileNotFoundError
        with pytest.raises(InternalError, match="/etc/resolv.conf not found"):
            utils.read_resolve_config()

    # Test read_resolve_config when permission is denied
    with patch("builtins.open", mock_open()) as m:
        m.side_effect = PermissionError
        with pytest.raises(InternalError, match="Permission denied to read /etc/resolv.conf"):
            utils.read_resolve_config()

    # Test read_resolve_config when an unexpected error occurs
    with patch("builtins.open", mock_open()) as m:
        m.side_effect = Exception
        with pytest.raises(InternalError, match="Failed to get DNS nameservers"):
            utils.read_resolve_config()


def test_resolve_host():
    # Valid hostname
    with patch("socket.gethostbyname") as mock_gethostbyname:
        mock_gethostbyname.return_value = "192.168.1.1"

        ip = utils.resolve_host("www.example.com")
        assert ip == "192.168.1.1"
        mock_gethostbyname.assert_called_once_with("www.example.com")

    # Valid hostname
    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        ip = utils.resolve_host("nonexistenthost")
        assert ip is None


@pytest.mark.parametrize("char", [
    "\b", "\n", "\t", "\r", "\f", "\v", "\x00", "\x01",
])
def test_get_char_width_with_control_chars(char):
    assert utils.get_char_width(char) == 0, f"Expected width of {char} to be 0"


@pytest.mark.parametrize("char", [
    "a", "b", "c", "A", "B", "C", "1", "2", "3", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "="
])
def test_get_char_width_with_ascii_chars(char):
    assert utils.get_char_width(char) == 1, f"Expected width of {char} to be 1"


@pytest.mark.parametrize("char", [
    "你", "我", "他", "爱", "美", "梦", "想"
])
def test_get_char_width_with_chinese_chars(char):
    assert utils.get_char_width(char) == 2, f"Expected width of {char} to be 2"


def test_get_char_width_with_empty_string():
    with pytest.raises(TypeError):
        utils.get_char_width("")


@pytest.mark.parametrize("text,width,expected_output", [
    ("hello", 5, "hello"),
    ("hello", 3, "hello"),
    ("hello", 10, "  hello   "),
    ("你好", 6, " 你好 "),
    ("你好 hello", 14, "  你好 hello  "),
])
def test_center_text(text, width, expected_output):
    result = utils.center_text(text, width)
    assert result == expected_output, f"Testing text={text}, width={width}"


@pytest.mark.parametrize("text,width,expected_output", [
    ("hello", 10, "hello     "),
    ("hello", 5, "hello"),
    ("hello", 3, "hello"),
    ("你好", 5, "你好 "),
    ("你好 hello", 12, "你好 hello  "),
])
def test_fill_text(text, width, expected_output):
    result = utils.fill_text(text, width)
    assert result == expected_output, f"Testing text={text}, width={width}"


@pytest.mark.parametrize("text,width,expected_output", [
    ("this is a test", 10, ["this is a ", "test      "]),
    ("this is\nanother test", 10, ["this is\nano", "ther test "]),
    ("这是一个测试样例", 10, ["这是一个测", "试样例    "]),
    ("这是一个a测试样例", 10, ["这是一个a ", "测试样例  "]),
    ("你好", 1, [" ", "你", "好"]),
    ("narrow", 1, ["n", "a", "r", "r", "o", "w"]),
])
def test_split_text_to_fixed_width(text, width, expected_output):
    assert utils.split_text_to_fixed_width(text, width) == expected_output


@pytest.mark.parametrize("text,width,expected_output", [
    ("This is a sample text to test the function.", 10, ["This is a ", "  sample  ", " text to  ", " test the ", "function. "]),
    ("One two three four", 5, [" One ", " two ", "three", "four "]),
])
def test_split_text_to_fixed_width_without_word_break(text, width, expected_output):
    assert utils.split_text_to_fixed_width_without_word_break(text, width) == expected_output


def test_wrap_text_by_line_width():
    result = utils.wrap_text_by_line_width("This is a long line of text to wrap.", 10)
    expected = "This is a \nlong line \nof text to\n wrap.    "
    assert result == expected

    result = utils.wrap_text_by_line_width("abcdefg", 1)
    expected = "a\nb\nc\nd\ne\nf\ng"
    assert result == expected

    result = utils.wrap_text_by_line_width("", 5)
    expected = ""
    assert result == expected

    result = utils.wrap_text_by_line_width("Short text", 11)
    expected = "Short text "
    assert result == expected

    result = utils.wrap_text_by_line_width("Exact width", 11)
    expected = "Exact width"
    assert result == expected
