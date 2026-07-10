# Security Policy

license-management-core is a **verification-only** cryptographic library: it holds no
private keys and never signs anything. Still, a verification bypass would be a
serious vulnerability for every application that relies on it.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Email **info@hymma.net** with the details (a proof-of-concept token or a
failing test vector is ideal). You will get an acknowledgement within 72
hours. We ask for up to 90 days to ship a fix before public disclosure, and
we will credit you in the release notes unless you prefer otherwise.

## Scope

In scope:

- Signature verification bypass (accepting a token the vendor key did not sign)
- Parser memory safety (JWS / JSON / base64url / SMBIOS handling of hostile input)
- License-status evaluation errors that grant access an expired or
  tampered license should not have

Out of scope:

- Attacks requiring a compromised vendor private key
- Clock manipulation on devices that do not wire up the trusted-time port
  (documented limitation)
- The License-Management.com service itself (report those to the same
  address, but they are handled outside this repository)

## Supported versions

The latest minor release receives security fixes.
