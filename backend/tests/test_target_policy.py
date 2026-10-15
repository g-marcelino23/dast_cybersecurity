import socket
from unittest.mock import patch

import pytest

from app.core.target_policy import TargetPolicyError, validate_target


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:5173",
        "http://127.0.0.1:3001/api",
        "http://[::1]:8001/",
        "https://10.1.2.3",
        "http://172.16.0.1",
        "http://172.31.255.254",
        "http://192.168.1.2",
        "http://localhost./",
    ],
)
def test_allows_local_scope(url):
    assert validate_target(url).addresses


@pytest.mark.parametrize(
    "url",
    [
        "https://8.8.8.8",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0",
        "http://100.100.100.200",
        "http://172.15.1.1",
        "http://172.32.0.1",
        "http://192.0.0.1",
        "http://[::]",
        "http://[fe80::1]",
        "http://[fc00::1]",
        "http://[::ffff:127.0.0.1]",
        "http://[fe80::1%25eth0]",
        "ftp://127.0.0.1",
        "file:///etc/passwd",
        "//localhost/",
        "http://user:password@localhost",
        "http://@localhost",
        "http://localhost:0",
        "http://localhost:99999",
        "http://localhost/#fragment",
        "http://local host",
        "",
        "http://%31%32%37.0.0.1",
        "http://localhost\\@8.8.8.8",
        "http://localhost/\n",
    ],
)
def test_rejects_unsafe_urls(url):
    with pytest.raises(TargetPolicyError):
        validate_target(url)


def answer(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))


def test_private_hostname_and_mixed_dns():
    with patch("socket.getaddrinfo", return_value=[answer("10.0.0.3")]):
        assert validate_target("http://clinic.test").addresses == ("10.0.0.3",)
    with patch("socket.getaddrinfo", return_value=[answer("10.0.0.3"), answer("8.8.8.8")]):
        with pytest.raises(TargetPolicyError):
            validate_target("http://clinic.test")


def test_unresolvable_hostname():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(TargetPolicyError):
            validate_target("http://missing.test")


def test_verified_public_host_is_allowed_but_mixed_dns_is_rejected():
    with patch("socket.getaddrinfo", return_value=[answer("93.184.216.34")]):
        target = validate_target("https://app.example.test", ["app.example.test"])
        assert target.addresses == ("93.184.216.34",)
        with pytest.raises(TargetPolicyError):
            validate_target("https://other.example.test", ["app.example.test"])

    with patch(
        "socket.getaddrinfo",
        return_value=[answer("93.184.216.34"), answer("127.0.0.1")],
    ):
        with pytest.raises(TargetPolicyError):
            validate_target("https://app.example.test", ["app.example.test"])
