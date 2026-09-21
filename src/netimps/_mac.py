"""MAC address value type (internal).

An IEEE 802 hardware address modelled the way :mod:`ipaddress` models IP
addresses: an immutable value object compared and hashed by its canonical
bytes and -- like :class:`ipaddress.IPv4Address` -- equal only to another
value of its own type, exposing ``.packed`` rather than subclassing
:class:`bytes`.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import re as _re
from typing import Optional, Union

__all__ = ["MACAddress", "MACLike"]

#: Anything :class:`MACAddress` accepts. ``bytearray`` is listed because the
#: constructor takes one; ``bool`` is not, because it is rejected despite
#: being an ``int`` subclass.
MACLike = Union[str, int, bytes, bytearray, "MACAddress"]


class MACAddress:
    """An IEEE 802 MAC address.

    Accepts the common textual forms on construction -- colon
    (``AA:BB:CC:DD:EE:FF``), hyphen (``AA-BB-CC-DD-EE-FF``), dot per octet
    (``aa.bb.cc.dd.ee.ff``), dot/Cisco triplets (``aabb.ccdd.eeff``) or bare
    (``AABBCCDDEEFF``) -- as well as an ``int``, six raw ``bytes`` or
    ``bytearray``, or another ``MACAddress``. Separators may not be mixed
    (``00-11:22-33:44-55`` is rejected), and a ``bool`` is not taken as an
    integer even though Python says it is one.

    The value is normalised to lowercase and compared/hashed by its canonical
    bytes, so instances are usable as dict keys and set members.

    Equality holds **only against another** ``MACAddress``: comparing with
    text is ``False``, because no hash can agree with ``str``'s across every
    spelling of one address. Parse the text first::

        MACAddress.try_parse(text) == mac

    ``as_str(sep)`` renders the address with an arbitrary separator between
    octets; ``sep=""`` produces the bare form, and every separator the
    constructor accepts round-trips through it.
    """

    #: Compiled pattern matching the accepted textual MAC forms. Exposed as a
    #: class attribute so callers can pre-screen text with
    #: ``MACAddress._VALID_MAC.match(text)`` before attempting construction.
    #: Each separated form is spelled out on its own rather than as a shared
    #: ``[:.-]`` class, so one address cannot mix separators.
    _VALID_MAC = _re.compile(
        r"^(?:"
        r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"  # colon separated
        r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"  # hyphen separated
        r"|[0-9A-Fa-f]{2}(?:\.[0-9A-Fa-f]{2}){5}"  # dot separated, per octet
        r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"  # dot / Cisco triplets
        r"|[0-9A-Fa-f]{12}"  # bare, no separators
        r")$"
    )

    __slots__ = ("_octets",)

    #: Declared (not assigned) so a checker can type the slot: the first
    #: assignment reads ``value._octets``, which it otherwise cannot infer.
    _octets: bytes

    def __init__(self, value: MACLike) -> None:
        if isinstance(value, MACAddress):
            self._octets = value._octets
            return
        if isinstance(value, (bytes, bytearray)):
            octets = bytes(value)
            if len(octets) != 6:
                raise ValueError("MAC address must be 6 bytes, got %d" % len(octets))
            self._octets = octets
            return
        if isinstance(value, bool):
            # bool is an int subclass, so an unguarded int branch would turn a
            # stray flag into 00:00:00:00:00:01 instead of rejecting it.
            raise TypeError("Cannot build MACAddress from %r" % (type(value).__name__,))
        if isinstance(value, int):
            if value < 0 or value > 0xFFFFFFFFFFFF:
                raise ValueError("MAC integer out of range: %r" % (value,))
            self._octets = value.to_bytes(6, "big")
            return
        if isinstance(value, str):
            text = value.strip()
            if not self._VALID_MAC.match(text):
                raise ValueError("Invalid MAC address: %r" % (value,))
            hexdigits = _re.sub(r"[.:-]", "", text)
            self._octets = bytes.fromhex(hexdigits)
            return
        raise TypeError("Cannot build MACAddress from %r" % (type(value).__name__,))

    @classmethod
    def is_valid(cls, value: object) -> bool:
        """Return True if ``value`` can be parsed as a MAC. Never raises.

        The type-local spelling of ``netimps.is_valid(value, MACAddress)``,
        which is often what reads best at a call site::

            if MACAddress.is_valid(user_input):
                ...

        A classmethod rather than a staticmethod so a subclass validates
        against itself.

        Returns a plain ``bool`` and deliberately does **not** narrow
        ``value``: a :data:`typing.TypeGuard` here would let a checker certify
        ``user_input.packed`` on something that is still a ``str``, which is
        the unsoundness removed from the module-level ``is_valid`` in 0.1.0.
        Use :meth:`try_parse` when you want the parsed object.
        """
        try:
            cls(value)  # type: ignore[arg-type]
            return True
        except (ValueError, TypeError):
            return False

    @classmethod
    def try_parse(cls, value: object) -> "Optional[MACAddress]":
        """Return a ``MACAddress``, or ``None`` if ``value`` is not one.

        The type-local spelling of ``netimps.try_parse(value, MACAddress)``.
        Prefer it to :meth:`is_valid` followed by construction -- one call, and
        no window in which the two disagree. It is also how text is compared
        against a MAC, since :meth:`__eq__` does not coerce a ``str``::

            MACAddress.try_parse(user_input) == known_mac
        """
        try:
            return cls(value)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            return None

    def as_str(self, sep: str = ":", upper: bool = False) -> str:
        """Return the MAC as a string with ``sep`` between octets.

        Lowercase by default (the canonical form used by ``str(mac)`` and by
        equality/hashing); pass ``upper=True`` for the uppercase rendering
        favoured by Windows tooling and much vendor output::

            mac.as_str("-")               # 'aa-bb-cc-dd-ee-ff'
            mac.as_str("-", upper=True)   # 'AA-BB-CC-DD-EE-FF'

        ``sep`` always goes between *octets*, ``"."`` included: the Cisco
        triplet spelling ``aabb.ccdd.eeff`` is accepted on input but never
        produced, so that one separator does not quietly mean something
        different from the others. ``":"``, ``"-"``, ``"."`` and ``""`` all
        parse back through the constructor; any other separator renders but
        does not round-trip.

        Case affects only this rendering -- two ``MACAddress`` values that
        differ solely in the case they were parsed from remain equal.
        """
        fmt = "%02X" if upper else "%02x"
        return sep.join(fmt % b for b in self._octets)

    @property
    def packed(self) -> bytes:
        """The 6 raw bytes of the address.

        The escape hatch for wire formats and syscalls, mirroring
        :attr:`ipaddress.IPv4Address.packed`. ``MACAddress`` deliberately is
        not a :class:`bytes` subclass -- see the class docstring.
        """
        return self._octets

    @property
    def oui(self) -> bytes:
        """The first three octets -- the vendor prefix -- **verbatim**.

        The I/G (group) and U/L (locally administered) flags live in the low
        two bits of octet 0 and are *not* masked out here, so for a multicast
        or locally administered address this is **not** a registered IEEE OUI:
        ``01:00:5e:00:00:01`` reports ``01:00:5e`` where the registered
        assignment is ``00:00:5e``. Mask them before a registry lookup::

            bytes([mac.oui[0] & 0xFC]) + mac.oui[1:]

        The bits are kept because this is the prefix as it appears on the wire
        and in this package's own output; :attr:`is_multicast` and
        :attr:`is_local` say when the masked form would differ.
        """
        return self._octets[:3]

    @property
    def is_multicast(self) -> bool:
        """True if the group bit (low bit of the first octet) is set.

        Multicast MACs are destinations only -- a NIC never *has* one -- so
        this is the check for "did I mistake a group address for a host?".
        """
        return bool(self._octets[0] & 0x01)

    @property
    def is_local(self) -> bool:
        """True if locally administered (the U/L bit is set).

        Locally administered addresses are assigned by software -- VMs,
        containers, and MAC-randomising clients -- rather than burned in by the
        vendor, so they are not stable identifiers.
        """
        return bool(self._octets[0] & 0x02)

    @property
    def is_universal(self) -> bool:
        """True if universally administered (vendor-assigned). Inverse of :attr:`is_local`."""
        return not self.is_local

    def __int__(self) -> int:
        return int.from_bytes(self._octets, "big")

    def __lt__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets < other._octets
        return NotImplemented

    def __le__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets <= other._octets
        return NotImplemented

    def __gt__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets > other._octets
        return NotImplemented

    def __ge__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets >= other._octets
        return NotImplemented

    def __str__(self) -> str:
        return self.as_str(":")

    def __repr__(self) -> str:
        return "MACAddress(%r)" % (self.as_str(":"),)

    def __eq__(self, other: object) -> bool:
        """Equal only to another :class:`MACAddress` -- never to text.

        Coercing a ``str`` here cannot be made lawful: every spelling of one
        address would compare equal, while ``str.__hash__`` -- not ours to
        change -- hashes each spelling differently, so ``mac == text`` and
        ``mac in {text}`` would silently disagree. Parse the text instead::

            MACAddress.try_parse(text) == mac

        Anything that is not a ``MACAddress`` yields ``NotImplemented``, so
        Python falls back to the reflected comparison and, failing that, to
        ``False`` -- a mismatch, never an exception.
        """
        if isinstance(other, MACAddress):
            return self._octets == other._octets
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._octets)
