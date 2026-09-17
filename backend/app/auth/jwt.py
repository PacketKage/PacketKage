"""Minimal RS256/ES256 JWT verification against a provider JWKS.

PacketKage deliberately validates ID tokens itself instead of trusting a
generic JWT library's defaults: every check required by the Authentik
integration (signature via the discovered JWKS, ``iss``, ``aud``/``azp``,
``nonce``, ``exp``/``nbf``) is explicit and raises a specific, actionable
error. Only asymmetric algorithms are accepted; ``alg: none`` and HS* are
rejected outright.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

ALLOWED_ALGS = {"RS256", "ES256"}


class JWTValidationError(ValueError):
    """An ID token failed one of the OIDC checks. ``reason`` is a short, specific label."""

    def __init__(self, reason: str, *, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_int(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


def verify_id_token(
    token: str,
    jwks: dict,
    *,
    issuer: str,
    audience: str,
    nonce: str,
    leeway: int = 30,
    now: float | None = None,
) -> dict[str, Any]:
    """Crypto + claims verification of an OIDC ID token.

    Returns the claims on success; raises :class:`JWTValidationError` with a
    ``reason`` in {malformed, unsupported_alg, missing_kid, unknown_key,
    bad_signature, expired, not_yet_valid, bad_issuer, bad_audience,
    bad_azp, bad_nonce} otherwise.
    """
    current = now if now is not None else time.time()
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTValidationError("malformed", detail="ID token is not a JWS with three segments")

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JWTValidationError("malformed", detail="ID token header/payload is not valid JSON") from exc

    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise JWTValidationError(
            "unsupported_alg",
            detail=f"ID token algorithm {alg!r} is not allowed (RS256/ES256 only)",
        )

    signature = b64url_decode(signature_b64)
    signing_input = f"{header_b64}.{payload_b64}".encode()

    public_key = _public_key_from_jwks(jwks, header, alg)
    if not _signature_ok(alg, public_key, signing_input, signature):
        raise JWTValidationError("bad_signature", detail="ID token signature verification failed")

    # ---- claims -----------------------------------------------------------
    if not _int_claim_satisfied(claims.get("exp"), current, leeway):
        raise JWTValidationError("expired")
    nbf = claims.get("nbf")
    if nbf is not None and isinstance(nbf, (int, float)) and float(nbf) - leeway > current:
        raise JWTValidationError("not_yet_valid")

    claim_iss = claims.get("iss")
    # Tolerate a trailing-slash-only difference (Authentik advertises the
    # issuer with one) while still requiring an exact match otherwise.
    if not isinstance(claim_iss, str) or claim_iss.rstrip("/") != issuer.rstrip("/"):
        raise JWTValidationError("bad_issuer", detail=f"issuer {claim_iss!r} != {issuer!r}")

    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if audience not in audiences:
        raise JWTValidationError("bad_audience", detail=f"aud {aud!r} does not include {audience!r}")

    azp = claims.get("azp")
    if azp is not None and azp != audience:
        raise JWTValidationError("bad_azp", detail=f"azp {azp!r} != {audience!r}")

    if claims.get("nonce") != nonce:
        raise JWTValidationError("bad_nonce")

    return dict(claims)


def _int_claim_satisfied(claim: Any, current: float, leeway: int) -> bool:
    """A claim (exp/nbf) is satisfied when it lies inside [current - leeway, +inf)."""
    if not isinstance(claim, (int, float)):
        return False
    if claim == float("inf") or claim == float("-inf"):
        return False
    return float(claim) >= current - leeway


def _public_key_from_jwks(jwks: dict, header: dict, alg: str):
    kid = header.get("kid")
    if kid is None:
        raise JWTValidationError("missing_kid", detail="ID token header has no 'kid'")

    keys = jwks.get("keys") or []
    match = next((k for k in keys if k.get("kid") == kid), None)
    if match is None:
        raise JWTValidationError("unknown_key", detail=f"No JWKS key with kid={kid!r}")

    try:
        if match.get("kty") == "RSA":
            return RSAPublicNumbers(_b64url_int(match["e"]), _b64url_int(match["n"])).public_key()
        if match.get("kty") == "EC":
            curve = _ec_curve(match.get("crv"))
            if curve is None:
                raise JWTValidationError("unsupported_alg", detail="Unsupported EC curve in JWKS")
            return EllipticCurvePublicNumbers(
                _b64url_int(match["x"]), _b64url_int(match["y"]), curve
            ).public_key()
    except (KeyError, ValueError) as exc:
        raise JWTValidationError("bad_jwk", detail=f"JWKS key {kid!r} is malformed: {exc}") from exc

    raise JWTValidationError("unsupported_alg", detail=f"Unsupported JWKS key type {match.get('kty')!r}")


def _ec_curve(crv: str | None) -> ec.EllipticCurve | None:
    if crv == "P-256":
        return ec.SECP256R1()
    if crv == "P-384":
        return ec.SECP384R1()
    return None


def _signature_ok(alg: str, public_key, signing_input: bytes, signature: bytes) -> bool:
    try:
        if alg == "RS256":
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True
        if alg == "ES256":
            # Accept both DER (openssl-style) and raw r||s (JOSE) encodings.
            candidate: bytes = signature
            if len(signature) == 64:
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

                candidate = encode_dss_signature(r, s)
            public_key.verify(candidate, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
    except Exception:
        return False
    return False
