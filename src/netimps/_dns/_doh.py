"""``resolve_doh``: one DNS-over-HTTPS endpoint (RFC 8484)."""

from __future__ import annotations

import socket as _socket
from typing import Any, Callable, List, Literal, Optional, Type, overload
from . import _dnswire
from .._exceptions import DNSDecodeError, ResolutionError, ResolutionTimeoutError
from .._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from ._wire import _question

#: The most a DoH reply may carry: the DNS message limit is 65,535 octets
#: (RFC 1035 section 4.2.2), and one more byte shows the limit was passed.
_DOH_MAX_BYTES = 65536


def _shown_url(url: str) -> str:
    """``url`` without its credentials, query string and fragment, for messages."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = "[%s]" % host
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host + (":%d" % port if port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _urllib_fetch(
    url: str, body: bytes, headers: "dict", timeout: Optional[float]
) -> bytes:
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        """A redirect is an HTTP error: the POST is not replayed elsewhere."""

        def redirect_request(self, *args: "Any", **kwargs: "Any") -> "Any":
            return None

    shown = _shown_url(url)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.build_opener(_NoRedirect).open(
            request, timeout=timeout
        ) as response:
            kind = (
                response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            )
            if kind != "application/dns-message":
                raise ResolutionError(
                    "%s answered %s, not application/dns-message"
                    % (shown, kind or "nothing")
                )
            data = response.read(_DOH_MAX_BYTES + 1)
            if len(data) > _DOH_MAX_BYTES:
                raise ResolutionError(
                    "%s answered a body larger than %d bytes" % (shown, _DOH_MAX_BYTES)
                )
            return data
    except ResolutionError:
        raise  # already says what was wrong with the reply
    except urllib.error.HTTPError as exc:
        raise ResolutionError("%s answered HTTP %d" % (shown, exc.code)) from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(exc, _socket.timeout) or isinstance(reason, _socket.timeout):
            raise ResolutionTimeoutError("%s: %s" % (shown, reason)) from exc
        raise ResolutionError("%s: %s" % (shown, reason)) from exc


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['a', 'A']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
    allow_http: bool = False,
) -> "List[IPv4Address]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['aaaa', 'AAAA']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
    allow_http: bool = False,
) -> "List[IPv6Address]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['ptr', 'PTR']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
    allow_http: bool = False,
) -> "List[str]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
    allow_http: bool = False,
) -> "List[Any]": ...


def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
    allow_http: bool = False,
) -> "List[Any]":
    """Resolve ``query`` with DNS over HTTPS (RFC 8484): the DNS message
    POSTed to ``url`` as ``application/dns-message``.

    ::

        resolve_doh("example.com", "https://cloudflare-dns.com/dns-query")

    :param fetch: ``fetch(url, body, headers, timeout) -> bytes`` sends the
        request -- so a caller with its own HTTP stack (a proxy, a CA bundle)
        uses it. ``None``: :mod:`urllib.request`, which follows no redirect and
        reads at most 65,536 bytes. An ``OSError`` or ``ValueError`` from it is
        a :class:`ResolutionError`.
    :param rdtype: as :func:`resolve_wire`.
    :param allow_http: accept an ``http://`` URL. Without it anything but
        ``https`` is a :class:`ValueError` before a request is made: a DNS
        answer over plain HTTP can be rewritten on the path.

    Contract as the other backends: native values, ``[]`` for NXDOMAIN or no
    record of the type, :class:`ResolutionError` when the endpoint could not
    be asked or answered something else (:class:`ResolutionTimeoutError` on a
    timeout), with an unreadable reply as the error's ``__cause__``
    (:class:`DNSDecodeError`). A ``query`` the codec cannot encode (an empty or
    over-long label) raises :class:`DNSDecodeError` itself, before anything is
    sent. Not part of :func:`resolve`'s chain. A reply body over 65,536 bytes, a
    redirect and an HTTP error status are :class:`ResolutionError`; messages
    name the URL without its credentials or query string.
    """
    from urllib.parse import urlsplit

    scheme = urlsplit(url).scheme.lower()
    if scheme != "https" and not (allow_http and scheme == "http"):
        raise ValueError(
            "DNS over HTTPS needs an https:// URL, got scheme %r; pass "
            "allow_http=True for a plain-http endpoint" % (scheme,)
        )
    query = _dst_argument(query)
    name, rdtype = _question(query, rdtype)
    payload = _dnswire.build_query(name, rdtype, 0)
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
    }
    shown = _shown_url(url)
    try:
        body = (fetch or _urllib_fetch)(url, payload, headers, timeout)
        if not _dnswire.is_reply_to(payload, body):
            raise DNSDecodeError("reply to another query")
        reply = _dnswire.parse_response(body, 0)
    except ResolutionError:
        raise
    except _socket.timeout as exc:
        raise ResolutionTimeoutError(
            "DNS over HTTPS via %s: %s" % (shown, exc)
        ) from exc
    except (OSError, ValueError) as exc:
        raise ResolutionError("DNS over HTTPS via %s: %s" % (shown, exc)) from exc
    if reply.rcode == _dnswire.NXDOMAIN:
        return []
    if reply.rcode != _dnswire.NOERROR:
        raise ResolutionError("%s answered rcode %d" % (shown, reply.rcode))
    return reply.records(name, rdtype)
