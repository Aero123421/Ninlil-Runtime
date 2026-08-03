#!/usr/bin/env python3
"""PA-S0 deterministic composition API.

The emission CLI is a thin caller and is never imported here.  This module
exposes construction to freshness checks only; acceptance is decided by the
separate independent/schema/R6/Python/Node/C11 authorities.
"""

from __future__ import annotations

from typing import Any


def compose_document() -> dict[str, Any]:
    """Rebuild the full Proposed PA-S0 document from pure construction.

    Does not read on-disk vectors. Implementation lives in the construction
    library module; this wrapper is the non-CLI import surface for expected_model.
    """
    import production_attachment_edhoc_composition as construction

    document = construction.build_document()
    if not isinstance(document, dict):
        raise TypeError("compose_document root")
    return document
