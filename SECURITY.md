# Security policy

## Supported version

Security fixes are provided for the latest released WSTG Flow version on supported Caido releases. Version 1.1 requires Caido 0.57 or newer.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, raw authenticated HTTP, or private target data. Use GitHub's private vulnerability reporting when it is available for `rust-memo/caido-wstg-flow`. If it is unavailable, open a minimal public issue that contains no vulnerability details or sensitive data and asks the maintainer to establish a private contact channel.

Include the WSTG Flow version, Caido version, affected behavior, impact, and a synthetic proof of concept. You should receive an acknowledgement within seven days.

## Safety boundaries

WSTG Flow's detectors must never send requests, follow links, download discovered assets, enumerate values, or publish a Finding without explicit tester confirmation. Replay actions may create an unsent draft only, and all evidence operations must respect Caido Scope and configured size limits.
