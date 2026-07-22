# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-07-18

### Added

- Initial release.
- IP factories `IPAddress`, `IPInterface`, `IPNetwork` (non-strict networks) over
  the standard library, plus concrete-type re-exports (`IPv4Address`, ...).
- `MACAddress` type: parses colon/hyphen/dot/bare forms, case-normalised,
  hashable, with `as_str(sep)` rendering and a `_VALID_MAC` pattern.
- Tolerant `parse_ip` / `parse_network` (empty input → `None`) and a
  non-raising `is_valid_ip`.
- `nslookup` (list-of-strings contract, `[]` on failure, uses `resolver.resolve`),
  `ping`, and local NIC helpers `active_nic_addresses` / `get_ip_address` /
  `nic_info`.

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jose-pr/netimps/releases/tag/v0.1.0
