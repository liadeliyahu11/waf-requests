"""WAFSession: transparent send -> classify -> transform -> retry ladder."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from . import learn
from . import profiles as profile_registry
from .blockpage import Status, classify
from .detect import cached_vendor, fingerprint, host_of
from .payloads import CATEGORIES, by_category
from .profiles import PROFILES, Profile, effective_limit
from .spec import ReqSpec, from_prepared, to_prepared
from .transforms import Ctx, TRANSFORMS

log = logging.getLogger("waf_requests")


@dataclass(frozen=True)
class AttemptLog:
    """One wire attempt: which candidate ran and what came back."""

    transform_id: "str | None"
    status: Status
    vendor: "str | None"
    evidence: str
    http_status: "int | None"
    summary: str


_RETRYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class _Resolved:
    profile: Profile
    limit: "int | None"


def _replay(send_fn, original, ladder, ctx, can_retry, max_attempts, verbose,
            profile_name, kwargs):
    """Run the transform ladder against ``original`` until a non-BLOCKED reply.

    Returns ``(response, attempts, winner)`` where ``winner`` is the transform
    id that delivered (``None`` means the untouched original delivered).
    """
    candidates: "list[tuple[str | None, object]]" = [(None, None)]
    for tid in ladder:
        candidates.append((tid, TRANSFORMS[tid]))

    attempts: "list[AttemptLog]" = []
    response, winner = None, None
    tried = 0
    for tid, transform in candidates:
        if tried >= max_attempts:
            break
        if tid is None:
            spec, summary, tier = original, "original request", "original"
        else:
            spec = transform.apply(original, ctx)  # type: ignore[attr-defined]
            if spec is None:
                continue  # inapplicable here; consumes no attempt
            summary, tier = transform.explain, transform.fidelity  # type: ignore[attr-defined]
        tried += 1

        response = send_fn(to_prepared(spec), **kwargs)
        verdict = classify(response)
        attempts.append(AttemptLog(
            transform_id=tid, status=verdict.status, vendor=verdict.vendor,
            evidence=verdict.evidence, http_status=response.status_code,
            summary=summary,
        ))
        if verbose:
            log.info("[%s] %d/%d %s[%s] -> %s (%s)",
                     profile_name, tried, max_attempts, tid or "original", tier,
                     verdict.status.value, response.status_code)
        if verdict.status is not Status.BLOCKED:
            winner = tid
            break
        if not can_retry:
            break
    return response, attempts, winner


def _substitute_payload(method, url, headers, body, marker, variant):
    """Build a ReqSpec with the ``{payload}`` marker replaced by ``variant``."""
    new_url = url.replace(marker, variant)
    new_headers = {
        k: (v.replace(marker, variant) if isinstance(v, str) else v)
        for k, v in (headers or {}).items()
    }
    new_body = None
    if body is not None:
        if isinstance(body, bytes):
            new_body = body.replace(marker.encode(), variant.encode())
        else:
            new_body = body.replace(marker, variant)
    return ReqSpec(method.upper(), new_url, new_headers, new_body)


class WAFSession(requests.Session):
    """Drop-in ``requests.Session`` that replays blocked requests.

    Attempt 0 is the untouched request. Each later attempt applies one
    transform from the profile's ladder to the original snapshot. The first
    response not classified BLOCKED wins; exhausted ladders return the last
    blocked response with :attr:`Response.waf_attempts` attached.

    ``learn=True`` promotes transforms that won on a host to the front of that
    host's ladder, persisted in a user-local file.
    """

    def __init__(
        self,
        profile: str = "auto",
        verbose: bool = False,
        max_attempts: int = 6,
        ladder: "tuple[str, ...] | None" = None,
        retry_mutating: bool = True,
        body_limit: "int | None" = None,
        strict_fidelity: bool = False,
        learn: bool = False,
    ) -> None:
        super().__init__()
        if ladder is not None:
            unknown = [tid for tid in ladder if tid not in TRANSFORMS]
            if unknown:
                raise ValueError(f"unknown transform ids in ladder: {unknown}")
        self.profile_name = profile
        self.verbose = verbose
        self.max_attempts = max(1, max_attempts)
        #: When True, differential transforms (which change the wire payload
        #: and depend on app parser behavior) are excluded; only transparent
        #: and additive transforms run, so the origin always interprets the
        #: original exploitation payload.
        self.strict_fidelity = strict_fidelity
        self.ladder_override = tuple(ladder) if ladder else None
        #: When False, only GET/HEAD/OPTIONS requests auto-retry after a block.
        self.retry_mutating = retry_mutating
        self.limit_override = body_limit
        self.learn = learn
        self._resolved: "dict[str, _Resolved]" = {}

    def _resolve_for(self, url: str) -> _Resolved:
        host = host_of(url)
        cached = self._resolved.get(host)
        if cached is not None:
            return cached

        if self.profile_name != "auto":
            profile = profile_registry.resolve(self.profile_name)
        else:
            parsed = urlparse(url)
            scheme = parsed.scheme or "http"
            vendor = cached_vendor(host) or fingerprint(f"{scheme}://{host}")
            if vendor and vendor in PROFILES:
                profile = PROFILES[vendor]
            else:
                profile = PROFILES["off"]
                log.warning(
                    "no WAF fingerprint for %r; sending unmodified "
                    "(run `python -m waf_requests detect <url>`)", host,
                )

        limit = self.limit_override or effective_limit(profile)
        resolved = _Resolved(profile=profile, limit=limit)
        self._resolved[host] = resolved
        return resolved

    def _ladder_for(self, host: str, resolved: _Resolved) -> "tuple[str, ...]":
        if self.ladder_override is not None:
            ladder = self.ladder_override
        elif self.learn:
            ladder = learn.learned_order(host, resolved.profile.ladder)
        else:
            ladder = resolved.profile.ladder
        if self.strict_fidelity:
            ladder = tuple(
                tid for tid in ladder
                if TRANSFORMS[tid].fidelity != "differential"
            )
        return ladder

    def _attach_metadata(self, response, attempts, transform_winner,
                         payload_variant=None, payload_tier=None) -> None:
        setattr(response, "waf_attempts", attempts)
        tier = "original" if transform_winner is None else TRANSFORMS[transform_winner].fidelity
        setattr(response, "payload_fidelity", {
            "transform": transform_winner,
            "tier": tier,
            "strict": self.strict_fidelity,
            # True means proven against an origin echo; None means assumed
            # from the tier; differential winners always need proof.
            "origin_verified": None,
            "note": (
                "origin-interpreted payload is identical by construction"
                if transform_winner is None or tier == "transparent"
                else "original fields intact plus distinct-name decoys"
                if tier == "additive"
                else "WIRE PAYLOAD DIFFERS - valid only if the app parser "
                     "normalizes as documented in the technique page"
            ),
            "payload_variant": payload_variant,
            "payload_tier": payload_tier,
        })

    def send(self, request, **kwargs):  # type: ignore[override]
        resolved = self._resolve_for(request.url)
        if resolved.profile.name == "off":
            return super().send(request, **kwargs)

        original = from_prepared(request)
        host = host_of(request.url)
        ladder = self._ladder_for(host, resolved)
        ctx = Ctx(profile_limit=resolved.limit)
        can_retry = self.retry_mutating or original.method in _RETRYABLE_METHODS

        response, attempts, winner = _replay(
            super().send, original, ladder, ctx, can_retry, self.max_attempts,
            self.verbose, resolved.profile.name, kwargs,
        )
        if self.learn and winner is not None:
            learn.record_win(host, winner)
        if response is not None:
            self._attach_metadata(response, attempts, winner)
        return response

    def exploit(self, method, url, payload, category, *,
                body=None, headers=None, payload_marker="{payload}",
                max_attempts=40, **send_kwargs):
        """Search payload-variant x request-transform candidates for a bypass.

        ``payload`` is the exploit string; ``category`` one of the ``CATEGORIES``
        values. The ``{payload}`` marker in ``url``/``headers``/``body`` is
        replaced with each payload variant (original first, then the category's
        mutators, transparent-first), and each variant runs the request ladder.
        First non-BLOCKED response wins; total sends are capped by
        ``max_attempts``.
        """
        if category not in CATEGORIES:
            raise ValueError(f"unknown payload category: {category!r}")

        variants = [("original", payload, "original")]
        variants += [(m.id, m.apply(payload), m.fidelity) for m in by_category(category)]

        resolved = self._resolve_for(url)
        host = host_of(url)
        ladder = self._ladder_for(host, resolved)
        ctx = Ctx(profile_limit=resolved.limit)
        can_retry = self.retry_mutating or method.upper() in _RETRYABLE_METHODS

        attempts: "list[AttemptLog]" = []
        response = None
        winner_transform = None
        winner_variant = None
        winner_tier = None
        budget = max(1, max_attempts)

        for variant_id, variant, variant_tier in variants:
            if budget <= 0:
                break
            spec = _substitute_payload(method, url, headers, body,
                                       payload_marker, variant)
            resp, atts, wtrans = _replay(
                super().send, spec, ladder, ctx, can_retry, budget,
                self.verbose, resolved.profile.name, send_kwargs,
            )
            attempts.extend(atts)
            budget -= len(atts)
            if resp is None:
                continue
            response = resp
            if classify(resp).status is not Status.BLOCKED:
                winner_transform, winner_variant, winner_tier = wtrans, variant_id, variant_tier
                break

        if self.learn and winner_transform is not None:
            learn.record_win(host, winner_transform)
        if response is not None:
            self._attach_metadata(response, attempts, winner_transform,
                                  winner_variant, winner_tier)
        return response
