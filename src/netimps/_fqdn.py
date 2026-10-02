"""A domain name as a value type, with path-like algebra (internal).

Re-exported from :mod:`netimps`.

**Read this first: the algebra is inverted from :mod:`pathlib`.** DNS label
order is the reverse of a filesystem path -- in ``www.example.com`` the *most*
significant label is last, not first. Every borrowed name therefore points the
other way::

    f = Fqdn("www.example.com")
    f.hostname          # 'www'               -- the LEFTmost label
    f.domain            # Fqdn('example.com') -- strips the LEFTmost label
    f.tld               # 'com'
    Fqdn("example.com") / "www"   # Fqdn('www.example.com')  -- PREPENDS

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

    Fqdn("example.com") != Fqdn("example.com.")

They are different queries. Compare ``.labels`` if you mean "the same labels
regardless of qualification".

Names, not addresses
--------------------
An address literal is **rejected**::

    Fqdn("10.0.0.1")   # ValueError
    Fqdn("::1")        # ValueError

:class:`netimps.Host` is the type for "an address *or* a name"; this one is a
name algebra, and labels, a parent domain and a TLD are things an IP does not
have. ``Host.fqdn`` bridges the two.

What this deliberately does not do
----------------------------------
There is **no ``registrable_domain``**. ``Fqdn("example.com").domain`` is
``Fqdn('com')`` -- a public suffix, not a registrant. Telling
``example.co.uk`` (registrable) from ``co.uk`` (not) requires the Public Suffix
List, a sizeable data file with its own update cadence, and this package has no
hard runtime dependencies. A heuristic that handles ``.com`` and mishandles
``.co.uk`` is worse than an honest gap, so the gap is documented instead.

There is also no ``reverse_pointer``: that is built from an address, and this
type has none. :meth:`Fqdn.reverse` flips *label order*, which is a different
operation with a similar name.
"""

from __future__ import annotations

import sys as _sys
from typing import Any, Iterable, Iterator, List, Optional, Tuple, Union

__all__ = ["Fqdn", "FqdnLike"]

#: What :class:`Fqdn` accepts wherever it accepts "another name": the parsed
#: type, a string, or an iterable of labels.
FqdnLike = Union["Fqdn", str]

#: RFC 1035 2.3.4. 253 rather than 255: the wire form spends one octet on each
#: label's length prefix and one on the root, so the printable form caps lower
#: than the oft-quoted 255.
MAX_NAME_LENGTH = 253

#: RFC 1035 2.3.4, per label.
MAX_LABEL_LENGTH = 63


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
        raise ValueError("label %r is not encodable as IDNA: %s" % (label, exc))


class Fqdn:
    """A domain name, with label algebra. Immutable, hashable and ordered.

    Built from a dotted string or from separate labels, **leftmost first** --
    the order they appear in the text::

        Fqdn("www.example.com")
        Fqdn("www", "example", "com")        # the same name
        Fqdn("www", Fqdn("example.com"))     # composition works too

    A trailing dot marks the name fully qualified and is preserved by
    ``str()``. See the module docstring for the pathlib inversion, the
    absoluteness rule, and the two things this type deliberately omits.

    :raises ValueError: for an address literal, an empty name, an over-long
        name or label, or an empty inner label (``a..b``).
    """

    __slots__ = ("_labels", "_absolute")

    _labels: "Tuple[str, ...]"
    _absolute: bool

    def __init__(self, *parts: "Union[FqdnLike, Iterable[str]]") -> None:
        labels: "List[str]" = []
        absolute = False

        flat: "List[Any]" = []
        for part in parts:
            if isinstance(part, (str, Fqdn)):
                flat.append(part)
            elif isinstance(part, Iterable):
                flat.extend(part)
            else:
                raise TypeError(
                    "Fqdn parts must be str, Fqdn or an iterable of labels, not %r"
                    % (type(part).__name__,)
                )

        if not flat:
            raise ValueError("Fqdn requires at least one label")

        for index, part in enumerate(flat):
            last = index == len(flat) - 1
            if isinstance(part, Fqdn):
                labels.extend(part._labels)
                if last and part._absolute:
                    absolute = True
                continue
            text = str(part).strip()
            if not text:
                # Caught here rather than falling through to the empty-label
                # check, which would report "consecutive dots" for a string
                # that has no dots at all.
                raise ValueError("a name cannot be empty")
            # Only the final part may carry the root dot; `Fqdn("a.", "b")`
            # would otherwise silently produce a name with a hole in it.
            if text.endswith(".") and text != ".":
                if not last:
                    raise ValueError(
                        "only the last part may end in a dot, got %r at position %d"
                        % (text, index)
                    )
                absolute = True
                text = text[:-1]
            if text == ".":
                if not last:
                    raise ValueError("the root label may only come last")
                absolute = True
                continue
            labels.extend(text.split(".") if "." in text else [text])

        if not labels:
            raise ValueError("Fqdn requires at least one label")

        # Reject an address *before* the label rules, so the error names the
        # real problem: "10.0.0.1" would otherwise pass every label check and
        # produce a nonsense "name". Routed through the package's own parser
        # rather than a second address detector.
        from . import is_valid
        from ._ip import IPAddress

        candidate = ".".join(labels)
        if is_valid(candidate, IPAddress) or is_valid(candidate.strip("[]"), IPAddress):
            raise ValueError(
                "%r is an IP address, not a domain name -- use netimps.Host for "
                "a value that may be either" % (candidate,)
            )

        encoded = []
        for label in labels:
            if not label:
                raise ValueError(
                    "empty label in %r -- consecutive dots are not a name"
                    % (candidate,)
                )
            label = _idna_encode(label)
            if len(label) > MAX_LABEL_LENGTH:
                raise ValueError(
                    "label %r is %d octets, over the %d-octet limit"
                    % (label, len(label), MAX_LABEL_LENGTH)
                )
            encoded.append(label)

        total = len(".".join(encoded))
        if total > MAX_NAME_LENGTH:
            raise ValueError(
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
    def try_parse(cls, value: object) -> "Optional[Fqdn]":
        """Return an :class:`Fqdn`, or ``None`` if ``value`` is not one.

        Prefer it to :meth:`is_valid` followed by construction -- one call, and
        no window in which the two disagree.
        """
        try:
            return cls(value)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            return None

    # -- the labels --------------------------------------------------------

    @property
    def labels(self) -> "Tuple[str, ...]":
        """The labels, **leftmost first**, without the root.

        ``Fqdn("www.example.com").labels == ("www", "example", "com")``. The
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
    def domain(self) -> "Optional[Fqdn]":
        """The name with its **leftmost** label removed, or ``None`` at the top.

        ``Fqdn("www.example.com").domain == Fqdn("example.com")``. Absoluteness
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
    def parent(self) -> "Optional[Fqdn]":
        """Alias of :attr:`domain`, for readers coming from ``pathlib``."""
        return self.domain

    @property
    def domains(self) -> "Tuple[Fqdn, ...]":
        """Every enclosing domain, nearest first.

        ``Fqdn("a.b.example.com").domains`` is
        ``(Fqdn('b.example.com'), Fqdn('example.com'), Fqdn('com'))``.
        """
        out: "List[Fqdn]" = []
        current = self.domain
        while current is not None:
            out.append(current)
            current = current.domain
        return tuple(out)

    @property
    def parents(self) -> "Tuple[Fqdn, ...]":
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

    def as_fully_qualified(self) -> "Fqdn":
        """This name with the root dot, unchanged if it already has one."""
        if self._absolute:
            return self
        return self._from_labels(self._labels, True)

    def relative(self) -> "Fqdn":
        """This name without the root dot, unchanged if it has none."""
        if not self._absolute:
            return self
        return self._from_labels(self._labels, False)

    # -- algebra -----------------------------------------------------------

    def __truediv__(self, other: "Union[FqdnLike, Iterable[str]]") -> "Fqdn":
        """``domain / label`` **prepends** -- the right operand is more specific.

        ``Fqdn("example.com") / "www"`` is ``Fqdn('www.example.com')``. The
        opposite direction from ``PurePath.__truediv__``, because DNS puts the
        significant label last. Absoluteness comes from the left operand, which
        is the one holding the root.

        There is no reflected ``__rtruediv__``: with the right operand as the
        label, a reflected form would swap the operands' roles while producing
        the same string.
        """
        try:
            addition = other if isinstance(other, Fqdn) else Fqdn(other)
        except (ValueError, TypeError):
            return NotImplemented  # type: ignore[return-value]
        return self._from_labels(addition._labels + self._labels, self._absolute)

    def child(self, *labels: "Union[FqdnLike, Iterable[str]]") -> "Fqdn":
        """Spelled-out form of :meth:`__truediv__`, for several labels at once."""
        result = self
        for label in labels:
            result = result / label
        return result

    def with_hostname(self, hostname: str) -> "Fqdn":
        """Replace the leftmost label.

        ``Fqdn("www.example.com").with_hostname("mail")`` is
        ``Fqdn('mail.example.com')``. For a single-label name this replaces the
        whole name.
        """
        replacement = Fqdn(hostname)
        if len(replacement._labels) != 1:
            raise ValueError("with_hostname takes one label, got %r" % (hostname,))
        return self._from_labels(replacement._labels + self._labels[1:], self._absolute)

    def with_name(self, name: str) -> "Fqdn":
        """Alias of :meth:`with_hostname`, for readers coming from ``pathlib``."""
        return self.with_hostname(name)

    def is_subdomain_of(self, other: "FqdnLike") -> bool:
        """Whether this name sits under ``other``.

        A name is **not** a subdomain of itself, matching the ordinary reading
        of the word -- use ``==`` for that, or
        ``f == other or f.is_subdomain_of(other)`` for "at or under".
        Qualification is ignored, since ``example.com`` and ``example.com.``
        describe the same place in the tree.
        """
        suffix = other if isinstance(other, Fqdn) else Fqdn(other)
        if len(self._labels) <= len(suffix._labels):
            return False
        return self._labels[-len(suffix._labels) :] == suffix._labels

    def relative_to(self, other: "FqdnLike") -> "Fqdn":
        """The labels of this name that are not part of ``other``.

        ``Fqdn("www.example.com").relative_to("example.com")`` is
        ``Fqdn('www')``, always relative (never fully qualified -- a fragment
        of a name has no root).

        :raises ValueError: if this name is not under ``other``, mirroring
            ``PurePath.relative_to``.
        """
        suffix = other if isinstance(other, Fqdn) else Fqdn(other)
        if not self.is_subdomain_of(suffix):
            raise ValueError("%s is not under %s" % (self, suffix))
        return self._from_labels(self._labels[: -len(suffix._labels)], False)

    def reverse(self) -> "Fqdn":
        """The same labels in reverse order -- ``com.example.www``.

        A mechanical flip, for display and for building keys. **The result is
        not a resolvable name**; it is the labels the other way round. Note
        this is unrelated to a reverse DNS pointer, which is built from an
        address and so has no place on this type.
        """
        return self._from_labels(tuple(reversed(self._labels)), self._absolute)

    # -- network convenience, delegating rather than reimplementing ---------

    def resolve(self, **kwargs: "Any") -> "List[Any]":
        """Look this name up. Straight through to :func:`netimps.resolve`.

        Every keyword that function takes works here, ``strict=`` included. The
        fully-qualified form is passed on as such, so a name built with a
        trailing dot keeps bypassing the search list.
        """
        from . import resolve

        return resolve(str(self), **kwargs)

    def ping(self, **kwargs: "Any") -> "Any":
        """Ping this name. Straight through to :func:`netimps.ping`."""
        from . import ping

        return ping(str(self), **kwargs)

    def ip(self, **kwargs: "Any") -> "Optional[Any]":
        """The first address this name resolves to, or ``None``.

        The convenience spelling of ``self.resolve()[0]``, matching
        :meth:`netimps.Host.ip`'s shape -- though **not** its caching, since
        this type is immutable and a cache on it would be a lie about freshness.
        """
        found = self.resolve(**kwargs)
        return found[0] if found else None

    # -- plumbing ----------------------------------------------------------

    @classmethod
    def _from_labels(cls, labels: "Tuple[str, ...]", absolute: bool) -> "Fqdn":
        """Build without re-validating: the labels came from a valid name.

        Bypasses ``__init__`` deliberately. Every caller is slicing or
        reordering labels that already passed the length, IDNA and
        not-an-address checks, so re-running them would be wasted work -- and
        the address check in particular would *reject* a legitimate derived
        name: ``Fqdn("1.2.3.4.example.com").domain`` walks down to
        ``Fqdn('4.example.com')`` and then ``Fqdn('example.com')``, but a
        reversed name can pass through a form that parses as an address.
        """
        if not labels:
            raise ValueError("a name needs at least one label")
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
        name such as ``Fqdn("1.2.3.4.sub").reverse()``, so the same
        validation-free path the algebra uses is the right one here.
        """
        return (_rebuild_fqdn, (self._labels, self._absolute))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Fqdn is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Fqdn is immutable")

    def __str__(self) -> str:
        text = ".".join(self._labels)
        return text + "." if self._absolute else text

    def __repr__(self) -> str:
        return "Fqdn(%r)" % (str(self),)

    def __len__(self) -> int:
        """The number of labels, not the number of characters.

        ``len(Fqdn("www.example.com")) == 3``. Use ``len(str(f))`` for octets.
        """
        return len(self._labels)

    def __iter__(self) -> "Iterator[str]":
        return iter(self._labels)

    def __contains__(self, label: object) -> bool:
        """Whether a *label* is present, compared case-insensitively."""
        if not isinstance(label, str):
            return False
        return label.lower() in tuple(part.lower() for part in self._labels)

    def __getitem__(self, index: "Any") -> "Any":
        """Index or slice the labels, leftmost first.

        A slice returns a plain tuple of labels rather than an ``Fqdn``,
        because an arbitrary slice of a name is usually not a name.
        """
        return self._labels[index]

    def _key(self) -> "Tuple[str, ...]":
        """Case-folded labels. RFC 4343: DNS comparison is case-insensitive."""
        return tuple(label.lower() for label in self._labels)

    def __eq__(self, other: object) -> bool:
        """Case-insensitive, and **qualification-sensitive**.

        ``Fqdn("EXAMPLE.com") == Fqdn("example.COM")`` is true (RFC 4343), but
        ``Fqdn("example.com") != Fqdn("example.com.")`` -- the trailing dot is
        the absoluteness marker, and the two are genuinely different queries.
        Compare ``.labels`` if qualification is not what you mean.

        Deliberately does **not** coerce a ``str``, for the same reason
        :class:`MACAddress` does not: it would make ``==`` disagree with
        ``hash`` across types. Use :meth:`try_parse` to compare against text.
        """
        if isinstance(other, Fqdn):
            return self._key() == other._key() and self._absolute == other._absolute
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._key(), self._absolute))

    def __lt__(self, other: object) -> bool:
        """Ordered on **reversed** labels, so sorting groups by TLD.

        ``sorted`` then gives ``com`` names together, and within them the
        registrants together -- which is almost always what a list of names
        wants. It is *not* the same as sorting ``str(f)``: that would put
        ``a.org`` before ``b.com``.
        """
        if not isinstance(other, Fqdn):
            return NotImplemented
        return tuple(reversed(self._key())) < tuple(reversed(other._key()))

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Fqdn):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Fqdn):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Fqdn):
            return NotImplemented
        return not self < other


def _rebuild_fqdn(labels: "Tuple[str, ...]", absolute: bool) -> "Fqdn":
    """Unpickle an :class:`Fqdn`. Module-level so pickle can find it by name."""
    return Fqdn._from_labels(labels, absolute)
