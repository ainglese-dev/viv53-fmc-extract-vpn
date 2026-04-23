#!/usr/bin/env python3
"""FMC S2S VPN full fact collector — extracts all classic manual fields."""

import json
import os
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = "https://fmcrestapisandbox.cisco.com"
DEFAULT_USER = "angeling"
DEFAULT_PASS = "U3P5__9ZF^y8oqvS"


def prompt(label, default):
    value = input(f"{label} [{default}]: ").strip()
    return value if value else default


FMC_HOST = prompt("FMC Host", DEFAULT_HOST).rstrip("/")
if "://" not in FMC_HOST:
    FMC_HOST = "https://" + FMC_HOST
USERNAME = prompt("Username", DEFAULT_USER)
PASSWORD = prompt("Password", DEFAULT_PASS)
DOMAIN_UUID = ""

BASE = f"{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
SESSION = requests.Session()
SESSION.verify = False

_CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "api_endpoints.json")
with open(_CFG_PATH) as _f:
    _API_CFG = json.load(_f)
_ENRICH  = {e["id"]: e for e in _API_CFG["enrichment"]}
_NET_CFG = _API_CFG["network_resolution"]


def authenticate():
    global DOMAIN_UUID, BASE
    url = f"{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = SESSION.post(url, auth=(USERNAME, PASSWORD))
    if r.status_code == 401:
        print("[!] Authentication failed: wrong username or password.")
        sys.exit(1)
    r.raise_for_status()
    SESSION.headers.update({"X-auth-access-token": r.headers["X-auth-access-token"]})
    DOMAIN_UUID = r.headers["DOMAIN_UUID"]
    BASE = f"{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
    print(f"[+] Authenticated (domain: {DOMAIN_UUID})")


def get_paginated(url, params=None):
    params = dict(params or {})
    params.setdefault("limit", 25)
    params.setdefault("offset", 0)
    all_items = []
    while True:
        r = SESSION.get(url, params=params)
        r.raise_for_status()
        data = r.json()
        all_items.extend(data.get("items", []))
        if "next" not in data.get("paging", {}):
            break
        params["offset"] += params["limit"]
    return all_items


def get_json(url):
    r = SESSION.get(url)
    r.raise_for_status()
    return r.json()


def resolve_network_object(obj_ref, max_depth=3):
    """Fetch full object data and add resolved_value to the ref dict in-place."""
    obj_type = obj_ref.get("type", "")
    obj_id   = obj_ref.get("id", "")
    if not obj_id:
        obj_ref["resolved_value"] = ""
        return obj_ref
    cfg = _NET_CFG.get(obj_type)
    if not cfg:
        obj_ref["resolved_value"] = ""
        return obj_ref
    url      = f"{BASE}/{cfg['path_template'].replace('{id}', obj_id)}"
    strategy = cfg["value_strategy"]
    try:
        data = get_json(url)
        if strategy == "value_field":
            obj_ref["resolved_value"] = data.get("value", "")
        elif strategy == "value_or_range":
            obj_ref["resolved_value"] = (
                data.get("value")
                or f"{data.get('startAddress','')}-{data.get('endAddress','')}"
            )
        elif strategy == "recursive_group" and max_depth > 0:
            members  = [resolve_network_object(m, max_depth - 1) for m in data.get("objects", [])]
            literals = [
                l.get("value") or f"{l.get('startAddress','')}-{l.get('endAddress','')}"
                for l in data.get("literals", [])
            ]
            all_vals = [m.get("resolved_value", m.get("name", "")) for m in members] + literals
            obj_ref["resolved_value"] = "; ".join(filter(None, all_vals))
        else:
            obj_ref["resolved_value"] = ""
    except requests.exceptions.HTTPError as e:
        print(f"     [!] resolve {obj_type} {obj_ref.get('name')}: {e.response.status_code}")
        obj_ref["resolved_value"] = ""
    return obj_ref


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def enrich_object(obj_ref, enrich_id):
    """Fetch an FMC object by ID and merge configured fields back into the reference."""
    cfg    = _ENRICH[enrich_id]
    obj_id = obj_ref.get("id", "")
    if not obj_id:
        return obj_ref
    url = f"{BASE}/{cfg['path_template'].replace('{id}', obj_id)}"
    try:
        details = get_json(url)
        for field in cfg["fields"]:
            obj_ref[field["name"]] = details.get(field["name"], field["default"])
    except requests.exceptions.HTTPError as e:
        print(f"     [!] {cfg['log_label']} {obj_ref.get('name')}: {e.response.status_code}")
    return obj_ref


def collect_ike_settings(topo_id, ike_ref):
    """Fetch full IKE settings by ID and enrich all embedded policy references."""
    ike_id = (ike_ref or {}).get("id")
    if not ike_id:
        return ike_ref or {}

    try:
        ike_full = get_json(f"{BASE}/policy/ftds2svpns/{topo_id}/ikesettings/{ike_id}")
    except requests.exceptions.HTTPError as e:
        print(f"     [!] ikesettings by ID: {e.response.status_code}")
        return ike_ref

    v2 = ike_full.get("ikeV2Settings", {})
    v2["policies"] = [enrich_object(p, "ikev2_policy") for p in v2.get("policies", [])]

    v1 = ike_full.get("ikeV1Settings", {})
    v1["policies"] = [enrich_object(p, "ikev1_policy") for p in v1.get("policies", [])]

    return ike_full


def collect_ipsec_settings(ipsec):
    """Enrich IPSec proposals in place (ipsec object already full from expanded list)."""
    ipsec["ikeV2IpsecProposal"] = [
        enrich_object(p, "ikev2_proposal") for p in ipsec.get("ikeV2IpsecProposal", [])
    ]
    ipsec["ikeV1IpsecProposal"] = [
        enrich_object(p, "ikev1_proposal") for p in ipsec.get("ikeV1IpsecProposal", [])
    ]
    return ipsec


def collect_endpoints(topo_id):
    """Fetch paginated endpoint list, then enrich each by ID."""
    try:
        ep_refs = get_paginated(f"{BASE}/policy/ftds2svpns/{topo_id}/endpoints")
    except requests.exceptions.HTTPError as e:
        print(f"     [!] endpoints list: {e.response.status_code}")
        return []

    full_endpoints = []
    for ep_ref in ep_refs:
        ep_id = ep_ref.get("id")
        if not ep_id:
            full_endpoints.append(ep_ref)
            continue
        try:
            ep_full = get_json(f"{BASE}/policy/ftds2svpns/{topo_id}/endpoints/{ep_id}")
            ep_full.pop("metadata", None)
            ep_full.pop("links", None)
            for net_ref in (ep_full.get("protectedNetworks") or {}).get("networks", []):
                resolve_network_object(net_ref)
            full_endpoints.append(ep_full)
        except requests.exceptions.HTTPError as e:
            print(f"     [!] endpoint {ep_ref.get('name')}: {e.response.status_code}")
            full_endpoints.append(ep_ref)
    return full_endpoints


def collect_s2s_vpns(domain_dir):
    topologies = get_paginated(
        f"{BASE}/policy/ftds2svpns",
        {"expanded": "true", "limit": 25},
    )
    print(f"[+] Found {len(topologies)} S2S VPN topology/ies")

    for topo in topologies:
        topo_id = topo["id"]
        topo_name = topo.get("name", "unknown")
        print(f"  -> {topo_name} ({topo.get('topologyType', '?')})")

        topo_context = {
            "name": topo_name,
            "id": topo_id,
            "type": topo.get("type"),
            "topologyType": topo.get("topologyType"),
            "routeBased": topo.get("routeBased"),
            "ikeV1Enabled": topo.get("ikeV1Enabled"),
            "ikeV2Enabled": topo.get("ikeV2Enabled"),
            "metadata": topo.get("metadata"),
            "ikeSettings": collect_ike_settings(topo_id, topo.get("ikeSettings")),
            "ipsecSettings": collect_ipsec_settings(topo.get("ipsecSettings", {})),
            "advancedSettings": topo.get("advancedSettings", {}),
        }

        record = {**topo_context, "endpoints": collect_endpoints(topo_id)}
        save_json(f"{domain_dir}/{topo_id}.json", record)
        print(f"     saved → {topo_id}.json")


def main():
    authenticate()
    domain_dir = f"./results/{DOMAIN_UUID}"
    os.makedirs(domain_dir, exist_ok=True)
    collect_s2s_vpns(domain_dir)
    print(f"\n[+] Results in {domain_dir}/")


if __name__ == "__main__":
    main()
