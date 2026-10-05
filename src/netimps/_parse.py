"""Generic ``parse`` / ``try_parse`` / ``is_valid`` (internal).

The one parsing entry point: ``type`` is a result type (the union aliases, a
concrete class) or any callable. The overloads under ``TYPE_CHECKING`` are the
signature callers see; the runtime definitions are permissive.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import inspect as _inspect
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Optional,
    TypeVar,
    Union,
    overload,
)
from typing import get_origin as _typing_get_origin

from ._exceptions import NetimpsValueError
from ._fqdn import FQDN
from ._ip._host import Host
from ._ip._types import (
    _BUILDER_DEFAULTS,
    _BUILDERS,
    _CONCRETE,
    IPAddress,
    IPInterface,
    IPNetwork,
)
from ._mac import MACAddress

if TYPE_CHECKING:
    # PEP 747's TypeForm preserves the result represented by runtime union
    # aliases such as IPAddress. Kept out of runtime imports so Python 3.9
    # gains no typing_extensions dependency.
    from typing_extensions import TypeForm

__all__ = ["parse", "try_parse", "is_valid", "classify"]

_ClassType = type  # ``parse`` and ``try_parse`` take a parameter named ``type``

#: The package's own value types, which have a ``parse`` classmethod.
_TEXT_TYPES = (MACAddress, FQDN, Host)

_T = TypeVar("_T")
_D = TypeVar("_D")


def _check_parser(type) -> None:
    """Raise TypeError unless ``type`` is something :func:`parse` can build with.

    Split out so :func:`try_parse` can validate before entering its
    ``except (ValueError, TypeError)`` block -- otherwise an unusable type is
    indistinguishable from a rejected value, and a caller bug returns the
    default instead of raising.
    """
    try:
        if type in _CONCRETE or type in _BUILDERS:
            return
    except TypeError:  # unhashable
        pass

    # A typing construct we do not build (an input-only ``*Like`` alias, or any
    # other Union) is a caller mistake, and must be rejected up front: on Python
    # 3.9 these objects *are* ``callable()`` -- ``Union[...](x)`` reaches
    # ``_GenericAlias.__call__`` -- so the callable check below would let them
    # past, to fail later with a far more confusing error.
    if _typing_get_origin(type) is not None:
        raise TypeError(
            "type must be a result type or a callable, got the typing "
            "construct %r (input-only aliases like IPAddressLike describe "
            "what is accepted, not what to build)" % (type,)
        )
    if not callable(type):
        raise TypeError("type must be a result type or a callable, got %r" % (type,))


if TYPE_CHECKING:
    # Runtime keeps one permissive implementation; these signatures preserve
    # the result represented by union type forms and arbitrary builders.
    #
    # Checking this file against *itself* raises two structural complaints a
    # caller never sees: the overloads have no implementation inside the
    # ``if TYPE_CHECKING`` block (``no-overload-impl``), and the runtime
    # ``def`` further down reads as a redefinition of them (``no-redef``).
    # Both are inherent to declaring overloads this way, so each is silenced
    # on the exact line that raises it -- never by loosening a signature.
    #
    # What callers actually get is asserted in ``tests/typing/api.py``
    # (``parse(x, IPNetwork)`` is typed ``IPv4Network | IPv6Network``, and so
    # on), and was measured from outside the package with ``TypeForm``
    # disabled and ``python_version = 3.9``. Do not flatten, widen or delete
    # these overloads to quiet the checker: that trades self-check noise for a
    # real loss of precision at every call site.
    @overload  # type: ignore[no-overload-impl]
    def parse(
        value: object,
        type: TypeForm[_T],
        *,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> _T: ...

    @overload
    def parse(
        value: object,
        type: Callable[..., _T],
        *,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> _T: ...

    @overload
    def parse(value: object) -> IPAddress: ...

    @overload  # type: ignore[no-overload-impl]
    def try_parse(
        value: object,
        type: TypeForm[_T],
        *,
        default: None = ...,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> Optional[_T]: ...

    @overload
    def try_parse(
        value: object,
        type: TypeForm[_T],
        *,
        default: _D,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> Union[_T, _D]: ...

    @overload
    def try_parse(
        value: object,
        type: Callable[..., _T],
        *,
        default: None = ...,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> Optional[_T]: ...

    @overload
    def try_parse(
        value: object,
        type: Callable[..., _T],
        *,
        default: _D,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> Union[_T, _D]: ...

    @overload
    def try_parse(value: object, *, default: None = ...) -> Optional[IPAddress]: ...

    @overload
    def try_parse(value: object, *, default: _D) -> Union[IPAddress, _D]: ...

    @overload  # type: ignore[no-overload-impl]
    def is_valid(
        value: object,
        type: TypeForm[_T],
        *,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> bool: ...

    @overload
    def is_valid(
        value: object,
        type: Callable[..., _T],
        *,
        strict: Optional[bool] = ...,
        **options: object,
    ) -> bool: ...

    @overload
    def is_valid(value: object) -> bool: ...


def parse(  # type: ignore[no-redef]  # the overloads above are the signature
    value: object,
    type: "object" = IPAddress,
    *,
    strict: "Optional[bool]" = None,
    **options: "object",
) -> "Any":
    """Build ``type`` from ``value``, raising on bad input.

    The single parsing entry point. ``type`` is a result type -- one of the
    :data:`IPAddress`/:data:`IPInterface`/:data:`IPNetwork` unions, a concrete
    ``IPv4Address`` &co, or any callable::

        parse("10.0.0.5")                        # IPv4Address  (the default)
        parse("10.0.0.5/24", IPInterface)        # IPv4Interface
        parse("10.0.0.5/24", IPNetwork)          # IPv4Network('10.0.0.0/24')
        parse("10.0.0.5/24", IPNetwork, strict=True)   # raises: host bits set
        parse("aa:bb:cc:dd:ee:ff", MACAddress)   # MACAddress

    Every type accepts the full range of stdlib inputs -- ``str``, ``int``,
    packed ``bytes``, or an existing object -- because the builders are the
    ``ipaddress.ip_*`` functions rather than the concrete constructors.

    A **union** accepts either family; a **concrete** type enforces its own, so
    ``parse("::1", IPv4Address)`` raises rather than quietly returning an
    ``IPv6Address``.

    Networks are parsed **non-strict** by default (unlike the stdlib), so a host
    address with a prefix normalises to its network instead of raising.
    ``strict`` is the network builders' option and is passed only when given;
    any other keyword passes through to the underlying builder.

    Raises :class:`NetimpsValueError` (a :class:`ValueError`) on malformed input
    or a family mismatch -- including the ``ipaddress`` builders' own errors --
    and :class:`TypeError` for an unusable ``type``. A callable ``type`` that is
    not one of the package's builders raises whatever it raises. Use
    :func:`try_parse` for the non-raising form.
    """
    target: Any = type
    kwargs: "Dict[str, Any]" = dict(options)
    if strict is not None:
        kwargs["strict"] = strict
    # Guarded: an unhashable ``type`` would make these lookups raise TypeError,
    # which try_parse would then swallow into `default` -- turning a caller bug
    # into a silent "invalid value". Fall through to the explicit checks below.
    try:
        wanted = _CONCRETE.get(target)
        builder = _BUILDERS.get(wanted if wanted is not None else target)
    except TypeError:
        wanted = builder = None

    if builder is None:
        _check_parser(target)  # raises for anything unusable
        # Text goes through the type's own ``parse``, so the spellings a type
        # accepts are defined in one place. Anything else (an ``int`` or
        # ``bytes`` MAC, a ``Host`` or ``FQDN`` already built) is the
        # constructor's, which ``parse`` deliberately does not take.
        if (
            isinstance(value, str)
            and isinstance(target, _ClassType)
            and issubclass(target, _TEXT_TYPES)
        ):
            return target.parse(value, **kwargs)
        return target(value, **kwargs)

    built = dict(_BUILDER_DEFAULTS.get(builder, {}))
    built.update(kwargs)
    try:
        result = builder(value, **built)
    except NetimpsValueError:
        raise
    except ValueError as exc:
        # `ipaddress` raises its own ValueError subclasses (`AddressValueError`,
        # `NetmaskValueError`) or a plain one; a caller catches one type.
        raise NetimpsValueError(str(exc)) from exc

    if wanted is not None and not isinstance(result, target):
        raise NetimpsValueError("%r is not a %s" % (value, target.__name__))
    return result


def _check_options(target: "Any", value: object, options: "Dict[str, Any]") -> None:
    """:class:`TypeError` for an option the callable that will receive it does
    not take, so a caller's mistake is not read as a rejected value.

    Skipped when the callable has a ``**`` parameter or no inspectable
    signature.
    """
    if not options:
        return
    try:
        wanted = _CONCRETE.get(target)
        builder = _BUILDERS.get(wanted if wanted is not None else target)
    except TypeError:
        return
    if builder is not None:
        receiver: "Any" = builder
    elif (
        isinstance(value, str)
        and isinstance(target, _ClassType)
        and issubclass(target, _TEXT_TYPES)
    ):
        receiver = target.parse
    else:
        receiver = target
    try:
        parameters = list(_inspect.signature(receiver).parameters.values())
    except (TypeError, ValueError):
        return
    if any(p.kind is p.VAR_KEYWORD for p in parameters):
        return
    names = {
        p.name
        for p in parameters
        if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
    }
    for key in options:
        if key not in names:
            raise TypeError(
                "%s() got an unexpected keyword argument %r"
                % (getattr(receiver, "__qualname__", repr(receiver)), key)
            )


#: Sentinel distinguishing "the parse returned None" from "it rejected the
#: input" -- ``None`` cannot do that job, since it is a legitimate result.
_MISSING = object()


def try_parse(  # type: ignore[no-redef]  # the overloads above are the signature
    value: object,
    type: "object" = IPAddress,
    *,
    default: "object" = None,
    strict: "Optional[bool]" = None,
    **options: "object",
) -> "Any":
    """Return ``type(value)``, or ``default`` if it rejects the input.

    A rejected value never raises; an unusable ``type`` or option does.

    The one non-raising parse for the whole package. ``type`` is either a
    **type** -- including the union aliases, which are not themselves callable
    -- or any callable that signals bad input with ``ValueError``/``TypeError``::

        try_parse("10.0.0.5", IPAddress)     # IPv4Address('10.0.0.5')
        try_parse("10.0.0.5", IPv4Address)   # concrete: v6 input rejected
        try_parse("nonsense", IPAddress)     # None
        try_parse(user_input, MACAddress) or DEFAULT_MAC
        try_parse(raw, IPAddress, default=LOCALHOST)   # explicit fallback

    The union aliases ``IPAddress``/``IPInterface``/``IPNetwork`` accept either
    family. A **concrete** type stays strict, so asking for one family and
    getting the other is impossible::

        try_parse("::1", IPAddress)      # IPv6Address('::1')  -- either family
        try_parse("::1", IPv4Address)    # None                -- v4 was asked for
        try_parse("10.0.0.5", IPv4Address)   # IPv4Address('10.0.0.5')

    Prefer this to ``is_valid`` followed by a parse: that pattern does the work
    twice and leaves a window where the two disagree.

    Generic in the type: ``try_parse(x, MACAddress)`` is typed
    ``Optional[MACAddress]``, so a checker knows the result without a cast.

    Only ``ValueError`` and ``TypeError`` are swallowed -- the two exceptions
    that mean "bad input". Anything else (an ``OSError`` from a builder that
    touches the network, a bug in it) propagates, because turning it
    into ``None`` would disguise a real failure as a rejected value. A
    ``type`` that is neither callable nor a known type raises ``TypeError``:
    that is a caller bug, not a rejected value.

    :param default: returned instead of ``None`` when the input is rejected.
        Also the seam :func:`is_valid` uses -- passing a sentinel is the only
        way to tell "the parse returned ``None``" from "it rejected the input".
    """
    # Validate the type *before* the try, so the TypeError raised for an
    # unusable one is not swallowed as if the value had been rejected. Only the
    # parse itself is guarded.
    target: Any = type
    _check_parser(target)
    kwargs = dict(options)
    if strict is not None:
        kwargs["strict"] = strict
    _check_options(target, value, kwargs)
    try:
        return parse(value, target, strict=strict, **options)
    except (ValueError, TypeError):
        return default


def is_valid(  # type: ignore[no-redef]  # the overloads above are the signature
    value: object,
    type: "object" = IPAddress,
    *,
    strict: "Optional[bool]" = None,
    **options: "object",
) -> "bool":
    """Return ``True`` if ``value`` parses as ``type``.

    A rejected value is ``False``, never an exception; an unusable ``type`` or
    option raises ``TypeError``, as in :func:`try_parse`.

    Accepts the same ``type`` forms as :func:`try_parse` -- a type, a union
    alias, or any callable::

        is_valid("10.0.0.5", IPAddress)      # True  (the type alias)
        is_valid("10.0.0.0/24", IPNetwork)   # True
        is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
        is_valid("nonsense", IPAddress)      # False

    When you want the parsed value too, use :func:`try_parse` instead of
    calling this first -- one call, no double work. Same exception policy: only
    ``ValueError``/``TypeError`` count as "invalid".

    .. note::
       A parser that legitimately returns ``None`` for valid input still counts
       as valid here -- the parse *succeeded*. That is why this delegates via a
       sentinel rather than testing ``try_parse(...) is not None``, which cannot
       tell "returned None" from "rejected the input".
    """
    target: Any = type
    return (
        try_parse(value, target, default=_MISSING, strict=strict, **options)
        is not _MISSING
    )


def classify(text: str) -> "Union[MACAddress, IPNetwork, IPInterface, IPAddress]":
    """Read ``text`` as whichever of a MAC, a network, an interface or an
    address it spells, and return that value.

    The order, which decides text that could be read two ways:

    1. a :class:`MACAddress` (any spelling it accepts);
    2. text with a ``/`` prefix length: an :data:`IPNetwork` when it has no
       host bits set (``"10.0.0.0/24"``, ``"10.0.0.5/32"``), otherwise an
       :data:`IPInterface` (``"10.0.0.5/24"``);
    3. an :data:`IPAddress` (``"10.0.0.5"``, ``"fe80::1%eth0"``).

    So a bare address is never read as a ``/32`` network, and an address with a
    prefix is never an address. A name is none of these: ``classify`` never
    asks a resolver, so ``classify("example.com")`` raises. Resolve it with
    :meth:`Host.resolve` first.

    Raises :class:`NetimpsValueError` for text that is none of them, and
    :class:`TypeError` for a non-``str``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str, got %r" % (type(text).__name__,))
    mac = try_parse(text, MACAddress)
    if mac is not None:
        return mac
    if "/" in text:
        network = try_parse(text, IPNetwork, strict=True)
        if network is not None:
            return network
        interface = try_parse(text, IPInterface)
        if interface is not None:
            return interface
    else:
        address = try_parse(text, IPAddress)
        if address is not None:
            return address
    raise NetimpsValueError(
        "%r is not a MAC address, network, interface or address" % (text,)
    )
