import platform
import distro

import requests
import socket
import psutil
import ipaddress

import unicodedata

from typing import Union, Tuple, List, Optional

from diagnose.exceptions import InternalError


def get_system_info() -> Tuple[str, str]:
    try:
        system = platform.system()
        release = platform.release()
        version = platform.version()
        if system == "Windows":
            return "Windows", f"Windows - {release} - (Version {version})"
        elif system == "Darwin":
            mac_version = platform.mac_ver()[0]
            return "MacOS", f"MacOS - {release} - (Version {mac_version})"
        elif system == 'Linux':
            linux_name = distro.name()
            linux_version = distro.version()
            return "Linux", f"{linux_name} - {release} - (Version {linux_version})"
        else:
            return "Unknown", "Unknown System"
    except Exception:
        return "Unknown", "Unknown System"


def is_valid_ip(ip_address: str):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_ip_address_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "IPv4"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return "IPv6"
    except ValueError:
        return "Error"


def is_ip_in_cidr(ip, cidr):
    try:
        ip_address = ipaddress.ip_address(ip)
        cidr_network = ipaddress.ip_network(cidr, strict=False)
        return ip_address in cidr_network
    except ValueError as ve:
        raise InternalError(f"Invalid IP address in function: {ve}")
    except Exception as e:
        raise InternalError(f"An unexpected error occurred in function: {e}")


def get_ipv4_interfaces():
    addrs = psutil.net_if_addrs()
    ipv4_interfaces = []
    for interface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                ipv4_interfaces.append({
                    "interface": interface,
                    "ip_address": addr.address
                })
    return ipv4_interfaces


def get_public_ip_address() -> Union[str, None]:
    ip_server_address = "https://ifconfig.me/ip"
    try:
        response = requests.get(ip_server_address, timeout=2)
        response.raise_for_status()
        if response.status_code == 200 and is_valid_ip(response.text):
            return response.text
        return None
    except requests.RequestException as e:
        return None
    finally:
        if "response" in locals():
            response.close()


def read_resolve_config() -> List[str]:
    resolve_config_path = "/etc/resolv.conf"
    nameservers = []
    try:
        with open(resolve_config_path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if line.startswith("nameserver"):
                splits = line.split()
                if len(splits) < 2:
                    continue
                nameservers.append(splits[1])
    except FileNotFoundError:
        raise InternalError("/etc/resolv.conf not found")
    except PermissionError:
        raise InternalError("Permission denied to read /etc/resolv.conf")
    except Exception:
        raise InternalError("Failed to get DNS nameservers")
    return nameservers


def resolve_host(hostname: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return None


def establish_tcp_connection(host: str, port: int, timeout: int = 2):
    client_socket = socket.create_connection((host, port), timeout)
    return client_socket


def can_establish_tcp_connection(host: str, port: int, timeout: int = 2) -> bool:
    try:
        establish_tcp_connection(host, port, timeout)
        return True
    except Exception:
        return False


def get_char_width(char: str) -> int:
    # Calculate the width of characters, where Chinese characters have a width of 2 and
    # English characters have a width of 1
    if unicodedata.category(char) == "Cc":  # Control character
        return 0
    width = unicodedata.east_asian_width(char)
    return 2 if width in "FW" else 1


def calculate_text_width(text: str) -> int:
    # Calculate the actual width of the text
    return sum(get_char_width(char) for char in text)


def center_text(text: str, width: int) -> str:
    real_width = calculate_text_width(text)

    if real_width < width:
        padding = width - real_width
        left_padding = padding // 2
        right_padding = padding - left_padding
    else:
        left_padding = 0
        right_padding = 0

    centered_text = " " * left_padding + text + " " * right_padding
    return centered_text


def fill_text(text: str, width: int) -> str:
    real_width = calculate_text_width(text)
    return text if real_width >= width else text + " " * (width - real_width)


def split_text_to_fixed_width(text: str, width: int) -> List[str]:
    lines = []
    current_line = ""
    current_length = 0

    for char in text:
        char_length = get_char_width(char)
        if current_length + char_length > width:
            current_line += " " * (width - current_length)
            lines.append(current_line)
            current_line = char  # new line
            current_length = char_length
        else:
            current_line += char
            current_length += char_length

    # Padding last line
    if len(current_line) > 0:
        current_line += " " * (width - current_length)
        lines.append(current_line)

    return lines


def split_text_to_fixed_width_without_word_break(text: str, width: int) -> List[str]:
    words = text.split()
    lines = []
    current_line = ""

    for word in words:
        word_width = calculate_text_width(word)
        if len(current_line) + word_width + 1 <= width:
            current_line += (word + " ")
        else:
            lines.append(current_line.rstrip())  # Remove trailing spaces
            current_line = word + " "  # New line

    # Last line
    if len(current_line) > 0:
        lines.append(current_line.rstrip())

    # Center text
    for i in range(len(lines)):
        lines[i] = center_text(lines[i], width)

    return lines


def wrap_text_by_line_width(text: str, width: int) -> str:
    return "\n".join(split_text_to_fixed_width(text, width))