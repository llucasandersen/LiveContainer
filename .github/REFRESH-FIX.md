The 2026-10-24 phone reports all identify SideStore UUID
14da04f3-7890-3350-a6da-9bdabb337122, CodeSignKit ASN1Helper.parseTLV
at image offset 0x7154f0. The caller is PKCS12Parser, reached through
CertificateManager.loadEmbeddedCertificate while probing certificate passwords.
No device identifiers, pairing files or certificate material are committed.

The packaging patch changes the invalid negative-range and signed length-addition
overflow traps into branches to the existing optional-nil return. It preserves
normal parsing and signing checks. The exact nightly UUID and original instruction
bytes must match, otherwise packaging fails for manual review.

Regression tests execute the actual ARM64 helper using Unicorn, reproducing both
old traps, checking safe nil returns, preserving four valid ASN.1 results, and
checking 200 deterministic malformed inputs. Foundation Data accessors are stubbed.
This verifies the diagnosed failure; successful signed on-device refresh still
requires testing after installing the resulting IPA.

Test dependencies live in requirements-test.txt and are build-host-only. Update
that file whenever a test introduces another third-party import.
