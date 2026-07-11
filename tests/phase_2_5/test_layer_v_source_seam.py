# tests/phase_2_5/test_layer_v_source_seam.py
"""Contract: Layer V uses the SEALED R2 path (injectable CT source), and the
apex-subdomain authorization is a first-class, apex-bounded Conductor step.

Anti-Lyndon #2 (dead code = done): Layer V must exercise passive_discovery's real
parse/partition/seed, not a bespoke crawl. The CT SOURCE is injectable so a lab
(where crt.sh is blind to a `.lab` TLD) can drive the real path offline. The source
is data, never a target — the exploited host still EMERGES from parsing.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_layer_v_source_seam.py -v
"""

from __future__ import annotations

import types
from typing import Any

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.live_fire.layer_v_runner import _authorize_apex_subdomains, load_layer_v_config
from agent_alpha.recon.passive_discovery import CRTSH_URL_TEMPLATE, PassiveDiscovery

_APEX = "odoo.lab"
_SUB = "vuln.odoo.lab"
_EXCLUDED = "hardened.odoo.lab"
_FOREIGN = "vuln.evil.example"  # NOT under the apex — must never be authorized

# A crt.sh-shaped payload: apex + one exploitable sub + one excluded co-host.
_CT_JSON = f'[{{"name_value":"{_APEX}\\n{_SUB}\\n{_EXCLUDED}"}}]'


class _Resp:
    def __init__(self, text: str) -> None:
        self.status_code = 200
        self.text = text
        self.headers: dict[str, str] = {}
        self.url = ""


class _CaptureClient:
    """Captures the exact URL R2 fetches, so we can prove which template was used."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(self.text)


def _engagement(store: InMemoryEventStore, domains: list[str]) -> tuple[Any, str]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("layer-v-lab", _APEX)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=domains, exclusions=[]))
    return auth, rec.engagement_id


def test_default_source_is_public_crtsh() -> None:
    store = InMemoryEventStore()
    auth, eid = _engagement(store, [_APEX])
    client = _CaptureClient(_CT_JSON)
    pd = PassiveDiscovery(http_client=client, authorization=auth, event_store=store)
    pd.discover(eid, _APEX)
    assert client.calls == [CRTSH_URL_TEMPLATE.format(domain=_APEX)]


def test_injected_lab_source_is_used_verbatim() -> None:
    store = InMemoryEventStore()
    auth, eid = _engagement(store, [_APEX])
    client = _CaptureClient(_CT_JSON)
    tmpl = "https://odoo.lab/ct/{domain}.json"
    pd = PassiveDiscovery(
        http_client=client, authorization=auth, event_store=store, crtsh_url_template=tmpl
    )
    result = pd.discover(eid, _APEX)
    # The injected SOURCE was fetched, and the subdomains EMERGED from parsing it.
    assert client.calls == ["https://odoo.lab/ct/odoo.lab.json"]
    assert _SUB in result.discovered
    assert _EXCLUDED in result.discovered


def test_authorize_apex_subdomains_promotes_only_bounded_and_unexcluded() -> None:
    store = InMemoryEventStore()
    auth, eid = _engagement(store, [_APEX])
    cfg = load_layer_v_config  # noqa: F841 — silence unused if import trimmed
    config = types.SimpleNamespace(
        root_domain=_APEX,
        scope_ip_ranges=[],
        scope_domains=[_APEX],
        scope_exclusions=[_EXCLUDED],
    )
    # discovered surface includes apex, the exploitable sub, an excluded co-host,
    # and a FOREIGN host that (defensively) must never be authorized.
    result = types.SimpleNamespace(discovered=(_APEX, _SUB, _EXCLUDED, _FOREIGN))

    authorized = _authorize_apex_subdomains(auth, eid, config, result)

    assert _SUB in authorized
    assert _APEX in authorized
    assert _EXCLUDED not in authorized  # excluded co-host stays default-DENY
    assert _FOREIGN not in authorized  # out-of-apex source entry can never widen scope

    # Conductor scope was actually extended (audited), so the sub is now in-scope
    # and the excluded/foreign hosts are not.
    assert auth.is_in_scope(eid, _SUB) is True
    assert auth.is_in_scope(eid, _EXCLUDED) is False
    assert auth.is_in_scope(eid, _FOREIGN) is False
