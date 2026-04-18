#!/usr/bin/env python3
"""FMC S2S VPN full fact collector — extracts all classic manual fields."""

import json
import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = "https://fmcrestapisandbox.cisco.com"
DEFAULT_USER = "angeling"
DEFAULT_PASS = "UR_CVk4K^b36dp6i"
DEFAULT_DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"


def prompt(label, default):
    value = input(f"{label} [{default}]: ").strip()
    return value if value else default


FMC_HOST = prompt("FMC Host", DEFAULT_HOST)
USERNAME = prompt("Username", DEFAULT_USER)
PASSWORD = prompt("Password", DEFAULT_PASS)
DOMAIN_UUID = prompt("Domain UUID (leave empty to auto-detect)", DEFAULT_DOMAIN)

BASE = f"{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
SESSION = requests.Session()
SESSION.verify = False


def authenticate():
    global DOMAIN_UUID, BASE
    url = f"{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = SESSION.post(url, auth=(USERNAME, PASSWORD))
    r.raise_for_status()
    SESSION.headers.update({"X-auth-access-token": r.headers["X-auth-access-token"]})
    if not DOMAIN_UUID:
        DOMAIN_UUID = r.headers["DOMAIN_UUID"]
        BASE = f"{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
        print(f"[+] Auto-detected Domain UUID: {DOMAIN_UUID}")
    print("[+] Authenticated")


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


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def enrich_ikev2_policy(pol_ref):
    """Fetch full IKEv2 policy object and merge into the reference."""
    try:
        details = get_json(f"{BASE}/object/ikev2policies/{pol_ref['id']}")
        pol_ref.update({
            "encryptionAlgorithms": details.get("encryptionAlgorithms", []),
            "integrityAlgorithms": details.get("integrityAlgorithms", []),
            "prfIntegrityAlgorithms": details.get("prfIntegrityAlgorithms", []),
            "diffieHellmanGroups": details.get("diffieHellmanGroups", []),
            "lifetimeInSeconds": details.get("lifetimeInSeconds"),
            "priority": details.get("priority"),
        })
    except requests.exceptions.HTTPError as e:
        print(f"     [!] ikev2policy {pol_ref.get('name')}: {e.response.status_code}")
    return pol_ref


def enrich_ikev1_policy(pol_ref):
    """Fetch full IKEv1 policy object and merge into the reference."""
    try:
        details = get_json(f"{BASE}/object/ikev1policies/{pol_ref['id']}")
        pol_ref.update({
            "encryptionAlgorithm": details.get("encryptionAlgorithm"),
            "hashAlgorithm": details.get("hashAlgorithm"),
            "diffieHellmanGroup": details.get("diffieHellmanGroup"),
            "lifetimeInSeconds": details.get("lifetimeInSeconds"),
            "authenticationMethod": details.get("authenticationMethod"),
        })
    except requests.exceptions.HTTPError as e:
        print(f"     [!] ikev1policy {pol_ref.get('name')}: {e.response.status_code}")
    return pol_ref


def enrich_ikev2_proposal(prop_ref):
    """Fetch full IKEv2 IPSec proposal and merge into the reference."""
    try:
        details = get_json(f"{BASE}/object/ikev2ipsecproposals/{prop_ref['id']}")
        prop_ref.update({
            "encryptionAlgorithms": details.get("encryptionAlgorithms", []),
            "integrityAlgorithms": details.get("integrityAlgorithms", []),
            "description": details.get("description", ""),
        })
    except requests.exceptions.HTTPError as e:
        print(f"     [!] ikev2ipsecproposal {prop_ref.get('name')}: {e.response.status_code}")
    return prop_ref


def enrich_ikev1_proposal(prop_ref):
    """Fetch full IKEv1 transform set and merge into the reference."""
    try:
        details = get_json(f"{BASE}/object/ikev1ipsecproposals/{prop_ref['id']}")
        prop_ref.update({
            "encryptionAlgorithm": details.get("encryptionAlgorithm"),
            "espHashAlgorithm": details.get("espHashAlgorithm"),
        })
    except requests.exceptions.HTTPError as e:
        print(f"     [!] ikev1ipsecproposal {prop_ref.get('name')}: {e.response.status_code}")
    return prop_ref


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
    v2["policies"] = [enrich_ikev2_policy(p) for p in v2.get("policies", [])]

    v1 = ike_full.get("ikeV1Settings", {})
    v1["policies"] = [enrich_ikev1_policy(p) for p in v1.get("policies", [])]

    return ike_full


def collect_ipsec_settings(ipsec):
    """Enrich IPSec proposals in place (ipsec object already full from expanded list)."""
    ipsec["ikeV2IpsecProposal"] = [
        enrich_ikev2_proposal(p) for p in ipsec.get("ikeV2IpsecProposal", [])
    ]
    ipsec["ikeV1IpsecProposal"] = [
        enrich_ikev1_proposal(p) for p in ipsec.get("ikeV1IpsecProposal", [])
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
