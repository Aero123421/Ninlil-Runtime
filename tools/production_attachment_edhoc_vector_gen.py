#!/usr/bin/env python3
"""Emission-only CLI for the Proposed Production Attachment PA-S0 vector.

All deterministic construction lives in
``production_attachment_edhoc_composition``.  Validation authority lives in
the independent schema, transition, R6, Python, Node and C11 modules; this CLI
is intentionally not imported by an expected-model validator.
"""

from __future__ import annotations

from production_attachment_edhoc_composition import main


if __name__ == "__main__":
    raise SystemExit(main())
