from utils.validators import (
    detect_ioc_type,
    extract_iocs,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_url,
    refang,
)


def test_refang():
    assert refang("hxxps[:]//example[.]com/a") == "https://example.com/a"


def test_ip_validation_rejects_invalid_octet():
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.8.8.8")


def test_domain_validation():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("sem-tld")


def test_url_validation():
    assert is_valid_url("https://example.com/login")
    assert not is_valid_url("javascript:alert(1)")


def test_email_validation():
    assert is_valid_email("analista@example.com")
    assert not is_valid_email("email-invalido")


def test_type_detection():
    assert detect_ioc_type("8.8.8.8") == "IP"
    assert detect_ioc_type("example.com") == "DOMAIN"
    assert detect_ioc_type("CVE-2024-21410") == "CVE"


def test_extract_defanged_iocs():
    result = extract_iocs(
        """
        hxxps[:]//evil[.]example/path
        8[.]8[.]8[.]8
        analyst[@]example[.]com
        CVE-2024-21410
        d41d8cd98f00b204e9800998ecf8427e
        """
    )

    assert "https://evil.example/path" in result.urls
    assert "8.8.8.8" in result.ips
    assert "analyst@example.com" in result.emails
    assert "CVE-2024-21410" in result.cves
    assert "d41d8cd98f00b204e9800998ecf8427e" in result.md5
