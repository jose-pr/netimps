"""The WS-Management schemes in the scheme registry.

A remote-execution library hard-coded ``5986 if ssl else 5985`` in three places
because ``get_default_port("winrm")`` was ``None``.
"""

import pytest

import netimps


@pytest.mark.parametrize(
    "scheme, port",
    [
        ("wsman", 5985),
        ("wsmans", 5986),
        ("winrm", 5985),
        ("winrms", 5986),
        ("psrp", 5985),
        ("WinRM", 5985),
        ("WINRMS", 5986),
    ],
)
def test_each_wsman_spelling_has_its_port(scheme, port):
    assert netimps.get_default_port(scheme) == port


def test_the_reverse_lookup_names_the_iana_scheme():
    """Several spellings share a port; the first registered is the canonical one
    (IANA's), not whichever alias happens to be last."""
    assert netimps.get_default_scheme(5985) == "wsman"
    assert netimps.get_default_scheme(5986) == "wsmans"


def test_the_ssh_and_http_canonical_names_are_unchanged():
    assert netimps.get_default_port("ssh") == 22
    assert netimps.get_default_scheme(80) == "http"
    assert netimps.get_default_scheme(443) == "https"
