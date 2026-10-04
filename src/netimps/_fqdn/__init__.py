"""A domain name as a value type, with path-like algebra (internal).

Re-exported from :mod:`netimps`.

**Read this first: the algebra is inverted from :mod:`pathlib`.** DNS label
order is the reverse of a filesystem path -- in ``www.example.com`` the *most*
significant label is last, not first. Every borrowed name therefore points the
other way::

    f = FQDN("www.example.com")
    f.hostname          # 'www'               -- the LEFTmost label
    f.domain            # FQDN('example.com') -- strips the LEFTmost label
    f.tld               # 'com'
    FQDN("example.com") / "www"   # FQDN('www.example.com')  -- PREPENDS

``PurePath`` would give you the rightmost component for ``.name`` and append on
``/``. If you assume pathlib semantics here you will get all of it backwards,
which is why the DNS spelling is the primary name and the pathlib one is an
alias on the same value: ``.domain``/``.parent``, ``.hostname``/``.name``,
``.labels``/``.parts``, ``.is_fully_qualified()``/``.is_absolute()``.

The trailing dot is absoluteness
--------------------------------
``example.com.`` is **fully qualified**; bare ``example.com`` is relative to
the resolver's search list and can resolve differently on different hosts.
:mod:`netimps._dns` already depends on the difference -- it appends a trailing
dot precisely to stop OS-level search expansion. So, exactly as
``Path("a") != Path("/a")``::

    FQDN("example.com") != FQDN("example.com.")

They are different queries. Compare ``.labels`` if you mean "the same labels
regardless of qualification".

Names, not addresses
--------------------
An address literal is **rejected**::

    FQDN("10.0.0.1")   # ValueError
    FQDN("::1")        # ValueError

:class:`netimps.Host` is the type for "an address *or* a name"; this one is a
name algebra, and labels, a parent domain and a TLD are things an IP does not
have. ``Host.fqdn()`` bridges the two.

What this deliberately does not do
----------------------------------
There is **no ``registrable_domain``**. ``FQDN("example.com").domain`` is
``FQDN('com')`` -- a public suffix, not a registrant. Telling
``example.co.uk`` (registrable) from ``co.uk`` (not) requires the Public Suffix
List, a sizeable data file with its own update cadence, and this package has no
hard runtime dependencies. A heuristic that handles ``.com`` and mishandles
``.co.uk`` is worse than an honest gap, so the gap is documented instead.

There is also no ``reverse_pointer``: that is built from an address, and this
type has none. :meth:`FQDN.reverse` flips *label order*, which is a different
operation with a similar name.
"""

from __future__ import annotations

from ._name import FQDN, FQDNLike, _rebuild_fqdn

__all__ = ["FQDN", "FQDNLike"]
