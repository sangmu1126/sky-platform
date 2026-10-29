"""Operator-pinned public build trust, never a source/model-selected key URL."""

import base64
import json

from application.kms_build_signature import KmsBuildSigningIdentity


def load_build_trust(raw, *, account_id, region):
    if not isinstance(raw, str) or not 1 <= len(raw) <= 8192:
        raise ValueError("Bounded operator build-signature trust configuration required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate build trust field")
            result[key] = value
        return result

    document = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "key_arn", "public_key_der_base64"}
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise ValueError("Exact public build trust registration required")
    identity = KmsBuildSigningIdentity(
        document["key_arn"], base64.b64decode(document["public_key_der_base64"], validate=True)
    )
    if (identity.account_id, identity.region) != (account_id, region):
        raise ValueError("Build trust registration is outside the approved account/region")
    return identity
