"""DNS resolution (internal).

Four independently callable backends, each returning a list of native values,
plus :func:`resolve` which tries them in order and returns the first
**non-empty** answer. A backend returns ``[]`` only when the resolver answered
that there is no such name or record; a resolver that could not be asked
raises :class:`ResolutionError` (:class:`ResolutionTimeoutError` for a
deadline), and only :func:`resolve` without ``strict`` turns that into ``[]``.

- :func:`resolve_dnspython` -- ``dnspython``, structured records, every
  ``rdtype``, explicit ``ns=``/``port=``/``search=`` control. Needs the ``dns``
  extra; :func:`has_dns` asks whether it is installed.
- :func:`resolve_system` -- :func:`socket.getaddrinfo`/
  :func:`socket.gethostbyaddr`, the OS resolver (hosts file, NSS, DNS).
  Address and reverse records (``a``/``aaaa``/``ptr``) only, no ``ns=``
  control -- it always asks the OS resolver, whatever that is configured to
  use.
- :func:`resolve_nslookup` -- shells out to the ``nslookup`` binary. Address
  and reverse records (``a``/``aaaa``/``ptr``) only, parsed from text output.
- :func:`resolve_wire` -- the DNS protocol itself, standard library only: UDP
  (TCP when truncated, or asked) to explicit nameservers, from an optional
  ``source`` address. In the chain only for an explicit ``ns=``/``source=``.

:func:`resolve_doh` asks one DNS-over-HTTPS endpoint (RFC 8484) and is not
part of the chain: a caller that names a DoH URL wants that answer alone.

``query`` accepts :data:`HostLike` everywhere (a hostname string, an
address string, an address object, or an interface object -- its ``.ip`` is
used). ``rdtype=None`` (the default on all four) auto-selects ``"ptr"`` for
an address-literal ``query`` and ``"a"`` otherwise.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

from ._cache import RESOLUTION_CACHE_TTL, clear_resolution_cache
from ._chain import resolve
from ._dnspython import has_dns, resolve_dnspython
from ._doh import resolve_doh
from ._lookup import lookup_fqdn, lookup_ip, resolver_keywords
from ._nslookup import resolve_nslookup
from ._system import _bounded_lookup, resolve_system
from ._wire import resolve_wire

__all__ = [
    "RESOLUTION_CACHE_TTL",
    "has_dns",
    "clear_resolution_cache",
    "resolve",
    "resolve_dnspython",
    "resolve_system",
    "resolve_nslookup",
    "resolve_wire",
    "resolve_doh",
]
