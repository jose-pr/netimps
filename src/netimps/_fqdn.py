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

import sys as _sys
from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)
from ipaddress import IPv4Address, IPv6Address

from ._dnswire import is_label
from ._exceptions import DNSDecodeError, NetimpsValueError

_IPAddress = Union[IPv4Address, IPv6Address]

__all__ = ["FQDN", "FQDNLike"]

#: What :class:`FQDN` accepts wherever it accepts "another name": the parsed
#: type, a string, or an iterable of labels.
FQDNLike = Union["FQDN", str]

#: RFC 1035 2.3.4. 253 rather than 255: the wire form spends one octet on each
#: label's length prefix and one on the root, so the printable form caps lower
#: than the oft-quoted 255.
MAX_NAME_LENGTH = 253

#: RFC 1035 2.3.4, per label.
MAX_LABEL_LENGTH = 63

#: The characters IDNA reads as a dot besides ``.`` (U+3002, U+FF0E, U+FF61).
_IDEOGRAPHIC_DOTS = {0x3002: ".", 0xFF0E: ".", 0xFF61: "."}

#: RFC 3986 section 2.2 general delimiters. The wire carries any printable
#: byte in a label, but text holding one of these is a URL or an address, not
#: a name, so `FQDN("http://example.com")` is refused rather than kept.
_URI_DELIMITERS = frozenset(":/?#[]@")

if TYPE_CHECKING:
    from ._ping import PingResult

_D = TypeVar("_D")
_F = TypeVar("_F", bound="FQDN")


def _idna_encode(label: str) -> str:
    """ASCII-encode one label, via IDNA where it is not already ASCII.

    Uses the standard library's ``str.encode("idna")``, which is **IDNA 2003**
    -- not the newer IDNA 2008 that the third-party ``idna`` package
    implements. The difference matters for a handful of names (notably the
    handling of ``ß`` and final sigma), and taking a dependency to fix that is
    not a trade this package makes. Documented rather than hidden.
    """
    if not label:
        return label
    try:
        label.encode("ascii")
        return label
    except UnicodeEncodeError:
        pass
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetimpsValueError("label %r is not encodable as IDNA: %s" % (label, exc))


class FQDN:
    """A domain name, with label algebra. Immutable, hashable and ordered.

    Built from a dotted string or from separate labels, **leftmost first** --
    the order they appear in the text::

        FQDN("www.example.com")
        FQDN("www", "example", "com")        # the same name
        FQDN("www", FQDN("example.com"))     # composition works too

    A trailing dot marks the name fully qualified and is preserved by
    ``str()``. See the module docstring for the pathlib inversion, the
    absoluteness rule, and the two things this type deliberately omits.

    :raises ValueError: for an address literal, an empty name, an over-long
        name or label, or an empty inner label (``a..b``).
    """

    __slots__ = ("_labels", "_absolute")

    _labels: "Tuple[str, ...]"
    _absolute: bool

    def __init__(self, *parts: "Union[FQDNLike, Iterable[Union[str, FQDN]]]") -> None:
        labels: "List[str]" = []
        absolute = False

        flat: "List[Union[str, FQDN]]" = []
        for part in parts:
            if isinstance(part, (str, FQDN)):
                flat.append(part)
            elif isinstance(part, (bytes, bytearray, memoryview)):
                raise TypeError(
                    "FQDN parts are text, not %r; decode the bytes, or use "
                    "FQDN.decode for the wire form" % (type(part).__name__,)
                )
            elif isinstance(part, Iterable):
                for item in part:
                    if not isinstance(item, (str, FQDN)):
                        raise TypeError(
                            "FQDN labels must be str or FQDN, not %r"
                            % (type(item).__name__,)
                        )
                    flat.append(item)
            else:
                raise TypeError(
                    "FQDN parts must be str, FQDN or an iterable of labels, not %r"
                    % (type(part).__name__,)
                )

        if not flat:
            raise NetimpsValueError("FQDN requires at least one label")

        for index, part in enumerate(flat):
            last = index == len(flat) - 1
            if isinstance(part, FQDN):
                labels.extend(part._labels)
                if last and part._absolute:
                    absolute = True
                continue
            # IDNA reads these as dots; splitting on them here keeps the
            # printed name and its labels the same thing.
            text = part.strip().translate(_IDEOGRAPHIC_DOTS)
            if not text:
                # Caught here rather than falling through to the empty-label
                # check, which would report "consecutive dots" for a string
                # that has no dots at all.
                raise NetimpsValueError("a name cannot be empty")
            # Only the final part may carry the root dot; `FQDN("a.", "b")`
            # would otherwise silently produce a name with a hole in it.
            if text.endswith(".") and text != ".":
                if not last:
                    raise NetimpsValueError(
                        "only the last part may end in a dot, got %r at position %d"
                        % (text, index)
                    )
                absolute = True
                text = text[:-1]
            if text == ".":
                if not last:
                    raise NetimpsValueError("the root label may only come last")
                absolute = True
                continue
            labels.extend(text.split(".") if "." in text else [text])

        if not labels:
            raise NetimpsValueError("FQDN requires at least one label")

        # IDNA first: the address and label rules apply to the ASCII a name
        # becomes, so a spelling that maps to `127.0.0.1` cannot get in.
        shown = ".".join(labels)
        encoded = []
        for label in labels:
            if not label:
                raise NetimpsValueError(
                    "empty label in %r -- consecutive dots are not a name" % (shown,)
                )
            label = _idna_encode(label)
            if len(label) > MAX_LABEL_LENGTH:
                raise NetimpsValueError(
                    "label %r is %d octets, over the %d-octet limit"
                    % (label, len(label), MAX_LABEL_LENGTH)
                )
            encoded.append(label)

        # Reject an address *before* the label rules, so the error names the
        # real problem: "10.0.0.1" would otherwise pass every label check and
        # produce a nonsense "name". Routed through the package's own parser
        # rather than a second address detector.
        from ._ip import IPAddress
        from ._parse import is_valid

        candidate = ".".join(encoded)
        if is_valid(candidate, IPAddress) or is_valid(candidate.strip("[]"), IPAddress):
            raise NetimpsValueError(
                "%r is an IP address, not a domain name -- use netimps.Host for "
                "a value that may be either" % (candidate,)
            )

        for label in encoded:
            if not is_label(label.encode("ascii")) or _URI_DELIMITERS.intersection(
                label
            ):
                raise NetimpsValueError(
                    "label %r cannot hold a space, a control character or "
                    "any of : / ? # [ ] @" % (label,)
                )

        total = len(candidate)
        if total > MAX_NAME_LENGTH:
            raise NetimpsValueError(
                "name is %d octets, over the %d-octet limit" % (total, MAX_NAME_LENGTH)
            )

        object.__setattr__(self, "_labels", tuple(encoded))
        object.__setattr__(self, "_absolute", absolute)

    # -- construction helpers, matching MACAddress's established shape ------

    @classmethod
    def is_valid(cls, value: object) -> bool:
        """True if ``value`` can be parsed as a domain name. Never raises.

        A classmethod rather than a staticmethod so a subclass validates
        against itself. Returns a plain ``bool`` and deliberately does not
        narrow ``value`` -- see :meth:`MACAddress.is_valid` for why a
        ``TypeGuard`` here would be unsound.
        """
        try:
            cls(value)  # type: ignore[arg-type]
            return True
        except (ValueError, TypeError):
            return False

    @classmethod
    def parse(cls: "Type[_F]", text: str) -> "_F":
        """Build an :class:`FQDN` from dotted text.

        :raises NetimpsValueError: for text that is not a domain name: an
            address literal, an empty or over-long name or label, an empty
            inner label. It is a ``ValueError``.
        :raises TypeError: for anything that is not ``str``. The constructor
            also takes labels and another ``FQDN``.
        """
        if not isinstance(text, str):
            raise TypeError("FQDN.parse takes text, not %r" % (type(text).__name__,))
        return cls(text)

    @overload
    @classmethod
    def try_parse(cls: "Type[_F]", text: str) -> "Optional[_F]": ...

    @overload
    @classmethod
    def try_parse(cls: "Type[_F]", text: str, default: _D) -> "Union[_F, _D]": ...

    @classmethod
    def try_parse(cls, text: str, default: Any = None) -> Any:
        """Return ``parse(text)``, or ``default`` for text that is not a name.

        Prefer it to :meth:`is_valid` followed by construction -- one call, and
        no window in which the two disagree.

        :raises TypeError: for anything that is not ``str``; only bad *text*
            is answered with ``default``. :func:`netimps.try_parse` is the
            entry that answers ``default`` for any object.
        """
        if not isinstance(text, str):
            raise TypeError(
                "FQDN.try_parse takes text, not %r" % (type(text).__name__,)
            )
        try:
            return cls(text)
        except ValueError:
            return default

    # -- the labels --------------------------------------------------------

    @property
    def labels(self) -> "Tuple[str, ...]":
        """The labels, **leftmost first**, without the root.

        ``FQDN("www.example.com").labels == ("www", "example", "com")``. The
        root is carried by :meth:`is_fully_qualified` rather than as an empty
        final label, because an empty string in this tuple would be a trap for
        every caller that iterates it.
        """
        return self._labels

    #: pathlib's spelling of :attr:`labels`. See the module docstring: the
    #: order is the reverse of ``PurePath.parts``.
    @property
    def parts(self) -> "Tuple[str, ...]":
        """Alias of :attr:`labels`, for readers coming from ``pathlib``."""
        return self._labels

    @property
    def hostname(self) -> str:
        """The **leftmost** label -- ``www`` in ``www.example.com``.

        The opposite end from ``PurePath.name``, which is the whole point of
        the inversion warning. For a single-label name this is the whole name.
        """
        return self._labels[0]

    @property
    def name(self) -> str:
        """Alias of :attr:`hostname`, for readers coming from ``pathlib``."""
        return self._labels[0]

    @property
    def tld(self) -> str:
        """The rightmost label -- ``com`` in ``www.example.com``.

        Deliberately has no ``.suffix`` alias: a filesystem suffix is part of a
        name (``.txt``) while a TLD is a whole label, so the analogy misleads.
        """
        return self._labels[-1]

    @property
    def domain(self) -> "Optional[FQDN]":
        """The name with its **leftmost** label removed, or ``None`` at the top.

        ``FQDN("www.example.com").domain == FQDN("example.com")``. Absoluteness
        is preserved.

        ``None`` for a single-label name, rather than a self-reference: pathlib
        makes ``Path("/").parent`` return itself, which is right for a
        filesystem root but would make ``while f.domain:`` loop forever here.

        **This is not the registrable domain.** The ``.domain`` of
        ``example.com`` is ``com``. See the module docstring.
        """
        if len(self._labels) <= 1:
            return None
        return self._from_labels(self._labels[1:], self._absolute)

    @property
    def parent(self) -> "Optional[FQDN]":
        """Alias of :attr:`domain`, for readers coming from ``pathlib``."""
        return self.domain

    @property
    def domains(self) -> "Tuple[FQDN, ...]":
        """Every enclosing domain, nearest first.

        ``FQDN("a.b.example.com").domains`` is
        ``(FQDN('b.example.com'), FQDN('example.com'), FQDN('com'))``.
        """
        out: "List[FQDN]" = []
        current = self.domain
        while current is not None:
            out.append(current)
            current = current.domain
        return tuple(out)

    @property
    def parents(self) -> "Tuple[FQDN, ...]":
        """Alias of :attr:`domains`, for readers coming from ``pathlib``."""
        return self.domains

    # -- qualification -----------------------------------------------------

    def is_fully_qualified(self) -> bool:
        """Whether the name carries the root dot, so needs no search list.

        The DNS reading of ``PurePath.is_absolute``. A relative name resolves
        against the resolver's search domains and can therefore mean different
        things on different hosts.
        """
        return self._absolute

    def is_absolute(self) -> bool:
        """Alias of :meth:`is_fully_qualified`."""
        return self._absolute

    def fully_qualified(self) -> "FQDN":
        """This name with the root dot, unchanged if it already has one."""
        if self._absolute:
            return self
        return self._from_labels(self._labels, True)

    def relative(self) -> "FQDN":
        """This name without the root dot, unchanged if it has none."""
        if not self._absolute:
            return self
        return self._from_labels(self._labels, False)

    # -- algebra -----------------------------------------------------------

    def __truediv__(self, other: "Union[FQDNLike, Iterable[str]]") -> "FQDN":
        """``domain / label`` **prepends** -- the right operand is more specific.

        ``FQDN("example.com") / "www"`` is ``FQDN('www.example.com')``. The
        opposite direction from ``PurePath.__truediv__``, because DNS puts the
        significant label last. Absoluteness comes from the left operand, which
        is the one holding the root.

        There is no reflected ``__rtruediv__``: with the right operand as the
        label, a reflected form would swap the operands' roles while producing
        the same string.
        """
        try:
            addition = other if isinstance(other, FQDN) else FQDN(other)
        except (ValueError, TypeError):
            return NotImplemented  # type: ignore[return-value]
        return self._from_labels(addition._labels + self._labels, self._absolute)

    def child(self, *labels: "Union[FQDNLike, Iterable[str]]") -> "FQDN":
        """Spelled-out form of :meth:`__truediv__`, for several labels at once."""
        result = self
        for label in labels:
            result = result / label
        return result

    def with_hostname(self, hostname: str) -> "FQDN":
        """Replace the leftmost label.

        ``FQDN("www.example.com").with_hostname("mail")`` is
        ``FQDN('mail.example.com')``. For a single-label name this replaces the
        whole name.
        """
        replacement = FQDN(hostname)
        if len(replacement._labels) != 1:
            raise ValueError("with_hostname takes one label, got %r" % (hostname,))
        return self._from_labels(replacement._labels + self._labels[1:], self._absolute)

    def with_name(self, name: str) -> "FQDN":
        """Alias of :meth:`with_hostname`, for readers coming from ``pathlib``."""
        return self.with_hostname(name)

    def is_subdomain_of(self, other: "FQDNLike") -> bool:
        """Whether this name sits under ``other``.

        A name is **not** a subdomain of itself, matching the ordinary reading
        of the word -- use ``==`` for that, or
        ``f == other or f.is_subdomain_of(other)`` for "at or under".
        Qualification is ignored, since ``example.com`` and ``example.com.``
        describe the same place in the tree.
        """
        suffix = other if isinstance(other, FQDN) else FQDN(other)
        if len(self._labels) <= len(suffix._labels):
            return False
        return self._key()[-len(suffix._labels) :] == suffix._key()

    def relative_to(self, other: "FQDNLike") -> "FQDN":
        """The labels of this name that are not part of ``other``.

        ``FQDN("www.example.com").relative_to("example.com")`` is
        ``FQDN('www')``, always relative (never fully qualified -- a fragment
        of a name has no root). Labels compare case-blind and the remainder
        keeps this name's spelling.

        :raises ValueError: if this name is not under ``other``, mirroring
            ``PurePath.relative_to``.
        """
        suffix = other if isinstance(other, FQDN) else FQDN(other)
        if not self.is_subdomain_of(suffix):
            raise ValueError("%s is not under %s" % (self, suffix))
        return self._from_labels(self._labels[: -len(suffix._labels)], False)

    def reverse(self) -> "FQDN":
        """The same labels in reverse order -- ``com.example.www``.

        A mechanical flip, for display and for building keys. **The result is
        not a resolvable name**; it is the labels the other way round. Note
        this is unrelated to a reverse DNS pointer, which is built from an
        address and so has no place on this type.
        """
        return self._from_labels(tuple(reversed(self._labels)), self._absolute)

    # -- network convenience, delegating rather than reimplementing ---------

    def resolve(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[FQDN, Optional[_IPAddress]]":
        """The pair ``(self, ip)``: this name, and the address it resolves to.

        The same shape as :meth:`netimps.Host.resolve`, so the two types
        answer ``.resolve()`` alike. The name is returned as it is -- no
        reverse lookup, and not the canonical name after search-list expansion.
        ``ip`` is ``None`` when nothing was found, or :class:`ResolutionError`
        is raised with ``check=True``. The fully-qualified form is asked as
        such, so a name with a trailing dot keeps bypassing the search list.

        The resolver options are those of :meth:`netimps.Host.ip`, including
        the rule that with none of ``ns``, ``port``, ``tcp``, ``source`` or
        ``backends`` only the OS resolver answers. DNS records of any type come
        from :func:`netimps.resolve`.
        """
        return (
            self,
            self.ip(
                check=check,
                ipv6=ipv6,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                backends=backends,
                source=source,
                cache=cache,
                deadline=deadline,
            ),
        )

    def ping(self, **kwargs: "Any") -> "PingResult":
        """Ping this name. Straight through to :func:`netimps.ping`."""
        from ._ping import ping

        return ping(str(self), **kwargs)

    def ip(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Optional[_IPAddress]":
        """The first address this name resolves to, or ``None``.

        Always a lookup, which can block, and **never memoised**: this type is
        immutable, and a cache on it would be a lie about freshness.
        :meth:`netimps.Host.ip` documents the options.
        """
        from ._dns import lookup_ip

        return lookup_ip(
            str(self),
            check=check,
            ipv6=ipv6,
            ns=ns,
            timeout=timeout,
            port=port,
            tcp=tcp,
            search=search,
            backends=backends,
            source=source,
            cache=cache,
            deadline=deadline,
        )

    # -- presentation and classification -----------------------------------

    def to_unicode(self) -> str:
        """The name in its display form, decoding punycode back to Unicode.

        Labels are stored ASCII-encoded, because that is what goes on the wire
        and what comparisons must use. This is the other direction, for showing
        a name to a person::

            FQDN("münchen.de").to_unicode()     # 'münchen.de'
            str(FQDN("münchen.de"))             # 'xn--mnchen-3ya.de'

        A label that is not valid punycode is passed through unchanged rather
        than raising -- ``xn--`` on its own is undecodable, and a display helper
        that throws is worse than one that shows the stored form.
        """
        out = []
        for label in self._labels:
            if label.lower().startswith("xn--"):
                try:
                    out.append(label.encode("ascii").decode("idna"))
                    continue
                except (UnicodeError, ValueError):
                    pass
            out.append(label)
        text = ".".join(out)
        return text + "." if self._absolute else text

    @property
    def is_wildcard(self) -> bool:
        """Whether the leftmost label is ``*`` -- a DNS wildcard name.

        A predicate only. Deliberately **no matching method**: DNS wildcards
        (RFC 4592) synthesise for names at any depth below the wildcard's
        parent, while TLS certificate matching (RFC 6125) allows exactly one
        label. Those are different answers for ``a.b.example.com`` against
        ``*.example.com``, and picking one silently would be wrong for half the
        callers. Write the rule you need against :meth:`is_subdomain_of`.
        """
        return self._labels[0] == "*"

    def is_hostname(self) -> bool:
        """Whether every label is a legal *host* name label (RFC 1123 LDH).

        Letters, digits and hyphens only, and no leading or trailing hyphen.

        This is **narrower than what this type accepts**, and deliberately so:
        plenty of real DNS names are not hostnames. ``_dmarc.example.com``,
        ``_sip._tcp.example.com`` and ``_acme-challenge.example.com`` all carry
        an underscore, and a wildcard carries ``*``. Rejecting them at
        construction would make the type useless for SRV, DMARC and ACME work,
        so the constructor takes the broad DNS rule and this reports the narrow
        one::

            FQDN("_dmarc.example.com").is_hostname()   # False -- but valid DNS
            FQDN("www.example.com").is_hostname()      # True
        """
        for label in self._labels:
            if not label or label[0] == "-" or label[-1] == "-":
                return False
            if not all(
                char.isascii() and (char.isalnum() or char == "-") for char in label
            ):
                return False
        return True

    def common_ancestor(self, other: "FQDNLike") -> "Optional[FQDN]":
        """The deepest domain enclosing both names, or ``None`` if unrelated.

        ``FQDN("a.example.com").common_ancestor("b.example.com")`` is
        ``FQDN('example.com')``. Compared from the right, since that is the end
        names share. Qualification follows this name's.

        ``None`` rather than an empty name when the two share no label at all:
        there is no such thing as a zero-label name, and the root is not a
        useful answer.
        """
        suffix = other if isinstance(other, FQDN) else FQDN(other)
        mine, theirs = self._key(), suffix._key()
        shared = 0
        for a, b in zip(reversed(mine), reversed(theirs)):
            if a != b:
                break
            shared += 1
        if not shared:
            return None
        return self._from_labels(
            self._labels[len(self._labels) - shared :], self._absolute
        )

    # -- wire form ---------------------------------------------------------

    def encode(self) -> bytes:
        """The DNS wire encoding: each label length-prefixed, root terminated.

        ``FQDN("www.example.com").encode()`` is
        ``b'\\x03www\\x07example\\x03com\\x00'``, uncompressed. Delegates to
        the package's own encoder, so it cannot drift from what
        :func:`netimps.resolve_wire` actually sends.

        Always absolute -- the root terminator is present whether or not this
        name carries a trailing dot, because there is no relative wire form.
        So :meth:`decode` of the result equals :meth:`fully_qualified`, which is
        this name only when it already is.
        """
        from ._dnswire import encode_name

        return encode_name(".".join(self._labels))

    def __bytes__(self) -> bytes:
        return self.encode()

    @classmethod
    def decode(cls: "Type[_F]", data: "Union[bytes, bytearray, memoryview]") -> "_F":
        """The name in a buffer that holds exactly one, in wire form.

        :raises DNSDecodeError: for a malformed name, a compression loop, or
            bytes left over after the name. It is a ``ValueError``.
        """
        buffer = bytes(data)
        name, end = cls.decode_at(buffer, 0)
        if end != len(buffer):
            raise DNSDecodeError("%d byte(s) follow the name" % (len(buffer) - end,))
        return name

    @classmethod
    def decode_at(
        cls: "Type[_F]", data: "Union[bytes, bytearray, memoryview]", offset: int
    ) -> "Tuple[_F, int]":
        """The name starting at ``offset`` in a DNS message, and where it ends.

        Follows compression pointers, with loop detection. The returned offset
        is the first byte after the name *in the record* -- just past the
        two-byte pointer when the name was compressed -- so the caller can
        carry on parsing from it. The name is always fully qualified.

        :raises DNSDecodeError: for an offset outside the message, a name that
            runs past it, a label over 63 octets, a name over 255, a compression
            loop, the root alone, or a label no :class:`FQDN` can hold (a
            non-printable byte or a dot). It is a ``ValueError``.
        """
        from ._dnswire import read_labels

        buffer = bytes(data)
        if not 0 <= offset <= len(buffer):
            raise DNSDecodeError("offset %d is outside the message" % (offset,))
        raw, end = read_labels(buffer, offset)
        if not raw:
            raise DNSDecodeError("the root has no labels, so it is not an FQDN")
        labels = []
        for label in raw:
            if not is_label(label):
                raise DNSDecodeError(
                    "label %r holds a byte an FQDN label cannot" % (label,)
                )
            labels.append(label.decode("ascii"))
        return cls._from_labels(tuple(labels), True), end

    @property
    def wire_length(self) -> int:
        """Octets this name occupies on the wire, root terminator included.

        This is the figure the **255**-octet protocol limit applies to, while
        the 253 limit checked at construction is on the printable form -- the
        difference being one length prefix per label plus the root. Worth
        reaching for when a name is going into a packet you are sizing.
        """
        return len(self.encode())

    # -- plumbing ----------------------------------------------------------

    @classmethod
    def _from_labels(
        cls: "Type[_F]", labels: "Tuple[str, ...]", absolute: bool
    ) -> "_F":
        """Build without re-validating: the labels came from a valid name.

        Bypasses ``__init__`` deliberately. Every caller is slicing,
        reordering or joining labels that already passed the IDNA, label and
        not-an-address checks, so re-running them would be wasted work -- and
        the address check in particular would *reject* a legitimate derived
        name: ``FQDN("1.2.3.4.example.com").domain`` walks down to
        ``FQDN('4.example.com')`` and then ``FQDN('example.com')``, but a
        reversed name can pass through a form that parses as an address. The
        total length is checked, since ``/`` and ``with_hostname`` grow a name.
        """
        if not labels:
            raise NetimpsValueError("a name needs at least one label")
        total = sum(len(label) for label in labels) + len(labels) - 1
        if total > MAX_NAME_LENGTH:
            raise NetimpsValueError(
                "name is %d octets, over the %d-octet limit" % (total, MAX_NAME_LENGTH)
            )
        instance = object.__new__(cls)
        object.__setattr__(instance, "_labels", tuple(labels))
        object.__setattr__(instance, "_absolute", bool(absolute))
        return instance

    def __reduce__(self) -> "Tuple[Any, Any]":
        """Pickle through :func:`_rebuild_fqdn`, not through ``__setstate__``.

        ``__slots__`` plus a blocked ``__setattr__`` defeats pickle's default
        restore, which assigns the state back onto a blank instance. Rebuilding
        from the labels is also *safer* than rebuilding from ``str(self)``: the
        constructor's not-an-address check would reject a legitimate derived
        name such as ``FQDN("1.2.3.4.sub").reverse()``, so the same
        validation-free path the algebra uses is the right one here.
        """
        return (_rebuild_fqdn, (self._labels, self._absolute, type(self)))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("FQDN is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("FQDN is immutable")

    def __str__(self) -> str:
        text = ".".join(self._labels)
        return text + "." if self._absolute else text

    def __repr__(self) -> str:
        return "FQDN(%r)" % (str(self),)

    def __add__(self, other: object) -> str:
        """``fqdn + str`` is a **plain string**, concatenated as text.

        For building a URL, a log line or a config value without reaching for
        ``str()`` first::

            FQDN("example.com") + "/health"      # 'example.com/health'
            "https://" + FQDN("example.com")     # 'https://example.com'

        A fully qualified name contributes its trailing dot, since that is what
        ``str()`` gives and ``+`` is defined as text concatenation.

        **Only a ``str`` is accepted.** ``FQDN + FQDN`` raises, pointing at
        ``/``: concatenating two names as text yields
        ``'www.example.comexample.com'``, which is never what anyone meant, and
        composing them is what ``/`` is for.
        """
        if isinstance(other, FQDN):
            raise TypeError(
                "cannot add two FQDN values as text -- use `/` to compose names "
                "(%r / %r), or str() on each if you really want concatenation"
                % (str(self), str(other))
            )
        if not isinstance(other, str):
            return NotImplemented  # type: ignore[return-value]
        return str(self) + other

    def __radd__(self, other: object) -> str:
        """``str + fqdn`` is a plain string. See :meth:`__add__`."""
        if not isinstance(other, str):
            return NotImplemented  # type: ignore[return-value]
        return other + str(self)

    def __len__(self) -> int:
        """The number of labels, not the number of characters.

        ``len(FQDN("www.example.com")) == 3``. Use ``len(str(f))`` for octets.
        """
        return len(self._labels)

    def __iter__(self) -> "Iterator[str]":
        return iter(self._labels)

    def __contains__(self, other: object) -> bool:
        """Whether ``other`` sits **at or under** this name -- ``name in domain``.

        The DNS reading of the stdlib's ``address in network``::

            FQDN("www.example.com") in FQDN("example.com")   # True
            "mail.example.com" in FQDN("example.com")         # True
            FQDN("example.com") in FQDN("example.com")        # True -- "at or under"
            FQDN("example.org") in FQDN("example.com")        # False

        **Inclusive**, unlike :meth:`is_subdomain_of`, which excludes the name
        itself. The pair mirrors ``<=`` against ``<``: a zone contains its own
        apex, exactly as a ``/24`` contains its network address, so ``in`` is the
        one that matches ``ipaddress``. Use ``is_subdomain_of`` when you mean
        *strictly* below.

        This is deliberately **not** a label test. An earlier version made
        ``"com" in FQDN("www.example.com")`` true, which reads plausibly and
        conflicts head-on with the containment meaning -- the same expression
        cannot answer both. Containment won because it is the stdlib idiom this
        package is a thin layer over, and because a label test is already
        spelled ``"com" in f.labels``.

        Accepts an :class:`FQDN` or a ``str``, ignores qualification (the
        trailing dot does not change where a name sits in the tree), and answers
        ``False`` rather than raising for anything unparseable -- which keeps it
        usable as a filter predicate.
        """
        if isinstance(other, FQDN):
            candidate: "Optional[FQDN]" = other
        elif isinstance(other, str):
            candidate = FQDN.try_parse(other)
        else:
            return False
        if candidate is None:
            return False
        if len(candidate._labels) < len(self._labels):
            return False
        return candidate._key()[-len(self._labels) :] == self._key()

    @overload
    def __getitem__(self, index: int) -> str: ...

    @overload
    def __getitem__(self, index: slice) -> "Tuple[str, ...]": ...

    def __getitem__(self, index: "Union[int, slice]") -> "Union[str, Tuple[str, ...]]":
        """Index or slice the labels, leftmost first.

        A slice returns a plain tuple of labels rather than an ``FQDN``,
        because an arbitrary slice of a name is usually not a name.
        """
        return self._labels[index]

    def _key(self) -> "Tuple[str, ...]":
        """Case-folded labels. RFC 4343: DNS comparison is case-insensitive."""
        return tuple(label.lower() for label in self._labels)

    def __eq__(self, other: object) -> bool:
        """Case-insensitive, and **qualification-sensitive**.

        ``FQDN("EXAMPLE.com") == FQDN("example.COM")`` is true (RFC 4343), but
        ``FQDN("example.com") != FQDN("example.com.")`` -- the trailing dot is
        the absoluteness marker, and the two are genuinely different queries.
        Compare ``.labels`` if qualification is not what you mean.

        Deliberately does **not** coerce a ``str``, for the same reason
        :class:`MACAddress` does not: it would make ``==`` disagree with
        ``hash`` across types. Use :meth:`try_parse` to compare against text.
        """
        if isinstance(other, FQDN):
            return self._key() == other._key() and self._absolute == other._absolute
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._key(), self._absolute))

    def _order_key(self) -> "Tuple[Tuple[str, ...], bool]":
        """The one key every comparison derives from: reversed folded labels,
        then absoluteness. Equal exactly when ``==`` is true."""
        return (tuple(reversed(self._key())), self._absolute)

    def __lt__(self, other: object) -> bool:
        """Ordered on **reversed** labels, so sorting groups by TLD.

        ``sorted`` then gives ``com`` names together, and within them the
        registrants together -- which is almost always what a list of names
        wants. It is *not* the same as sorting ``str(f)``: that would put
        ``a.org`` before ``b.com``. The same labels sort relative before fully
        qualified, and all four operators come from one key, so none of them
        contradicts ``==``.
        """
        if not isinstance(other, FQDN):
            return NotImplemented
        return self._order_key() < other._order_key()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, FQDN):
            return NotImplemented
        return self._order_key() <= other._order_key()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, FQDN):
            return NotImplemented
        return self._order_key() > other._order_key()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, FQDN):
            return NotImplemented
        return self._order_key() >= other._order_key()


def _rebuild_fqdn(
    labels: "Tuple[str, ...]", absolute: bool, cls: "Optional[Type[FQDN]]" = None
) -> "FQDN":
    """Unpickle an :class:`FQDN`, as ``cls`` when it is given. Module-level so
    pickle can find it by name."""
    return (cls or FQDN)._from_labels(labels, absolute)
