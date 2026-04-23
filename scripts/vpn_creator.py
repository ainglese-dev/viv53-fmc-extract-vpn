#!/usr/bin/env python3
"""Create varied S2S VPN topologies in FMC lab for test data coverage."""

import json
import sys
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = "https://fmcrestapisandbox.cisco.com"
DEFAULT_USER = "angeling"
DEFAULT_PASS = "U3P5__9ZF^y8oqvS"
DEFAULT_DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"


def prompt(label, default):
    value = input(f"{label} [{default}]: ").strip()
    return value if value else default


FMC_HOST = prompt("FMC Host", DEFAULT_HOST).rstrip("/")
if "://" not in FMC_HOST:
    FMC_HOST = "https://" + FMC_HOST
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


def get_json(url):
    r = SESSION.get(url)
    r.raise_for_status()
    return r.json()


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


def create_topology(name, topology_type, ikev1=False, ikev2=True):
    payload = {
        "name": name,
        "type": "FTDS2SVpn",
        "topologyType": topology_type,
        "ikeV1Enabled": ikev1,
        "ikeV2Enabled": ikev2,
    }
    r = SESSION.post(f"{BASE}/policy/ftds2svpns", json=payload)
    r.raise_for_status()
    return r.json()


def get_ike_setting(topo_id, ike_id):
    return get_json(f"{BASE}/policy/ftds2svpns/{topo_id}/ikesettings/{ike_id}")


def put_ike_setting(topo_id, ike_id, payload):
    r = SESSION.put(f"{BASE}/policy/ftds2svpns/{topo_id}/ikesettings/{ike_id}", json=payload)
    r.raise_for_status()
    return r.json()


def put_ipsec_setting(topo_id, ipsec_id, payload):
    r = SESSION.put(f"{BASE}/policy/ftds2svpns/{topo_id}/ipsecsettings/{ipsec_id}", json=payload)
    r.raise_for_status()
    return r.json()


def create_endpoint(topo_id, name, ip, peer_type, connection_type="BIDIRECTIONAL",
                    protected_networks=None):
    pn = {"networks": protected_networks} if protected_networks else {}
    payload = {
        "name": name,
        "type": "EndPoint",
        "extranet": True,
        "extranetInfo": {
            "name": name,
            "ipAddress": ip,
            "isDynamicIP": False,
        },
        "peerType": peer_type,
        "connectionType": connection_type,
        "enableNatTraversal": True,
        "allowIncomingIKEv2Routes": False,
        "protectedNetworks": pn,
    }
    r = SESSION.post(f"{BASE}/policy/ftds2svpns/{topo_id}/endpoints", json=payload)
    r.raise_for_status()
    return r.json()


def configure_ike_psk(topo_id, ike_id, psk, policy_ids):
    payload = {
        "id": ike_id,
        "type": "IkeSetting",
        "ikeV2Settings": {
            "authenticationType": "MANUAL_PRE_SHARED_KEY",
            "manualPreSharedKey": psk,
            "enforceHexBasedPreSharedKeyOnly": False,
            "policies": [{"id": pid, "type": "IKEv2Policy"} for pid in policy_ids],
        },
    }
    return put_ike_setting(topo_id, ike_id, payload)


def configure_ipsec(topo_id, ipsec_id, proposal_ids, pfs_enabled=False, lifetime_sec=3600):
    payload = {
        "id": ipsec_id,
        "type": "IPSecSetting",
        "cryptoMapType": "STATIC",
        "ikeV2Mode": "TUNNEL",
        "lifetimeSeconds": lifetime_sec,
        "lifetimeKilobytes": 4608000,
        "perfectForwardSecrecy": {"enabled": pfs_enabled},
        "enableRRI": False,
        "doNotFragmentPolicy": "NONE",
        "ikeV2IpsecProposal": [{"id": pid, "type": "IKEv2IPsecProposal"} for pid in proposal_ids],
        "tfcPackets": {"burstBytes": 0, "enabled": False, "payloadBytes": 0, "timeoutSeconds": 0},
        "enableSaStrengthEnforcement": False,
        "validateIncomingIcmpErrorMessage": False,
    }
    return put_ipsec_setting(topo_id, ipsec_id, payload)


def get_sub_ids(topo_id):
    """Return IKE settings ID and IPSec settings ID for a newly created topology."""
    topo = get_json(f"{BASE}/policy/ftds2svpns/{topo_id}")
    ike_id = (topo.get("ikeSettings") or {}).get("id")
    ipsec_id = (topo.get("ipsecSettings") or {}).get("id")

    if not ike_id:
        ike_list = get_paginated(f"{BASE}/policy/ftds2svpns/{topo_id}/ikesettings")
        ike_id = ike_list[0]["id"] if ike_list else None
    if not ipsec_id:
        ipsec_list = get_paginated(f"{BASE}/policy/ftds2svpns/{topo_id}/ipsecsettings")
        ipsec_id = ipsec_list[0]["id"] if ipsec_list else None

    return ike_id, ipsec_id


def create_network_object(obj_type, payload):
    """POST a network object; on 409 conflict, fetch and reuse the existing one."""
    endpoint_map = {"Network": "networks", "Host": "hosts", "Range": "ranges"}
    url = f"{BASE}/object/{endpoint_map[obj_type]}"
    r = SESSION.post(url, json={**payload, "type": obj_type})
    if r.status_code == 409:
        existing = get_paginated(
            f"{BASE}/object/{endpoint_map[obj_type]}",
            {"filter": f"nameOrValue:{payload['name']}"},
        )
        match = next((o for o in existing if o["name"] == payload["name"]), None)
        if match:
            return {"id": match["id"], "name": match["name"], "type": obj_type}
    r.raise_for_status()
    resp = r.json()
    return {"id": resp["id"], "name": resp["name"], "type": obj_type}


def pick_objs(objs, *names):
    """Return a list of object refs for the given names, skipping any that failed to create."""
    result = [objs[n] for n in names if n in objs]
    return result or None


def create_all_objects():
    """Create 8 named network objects covering Network, Host, and Range types."""
    specs = [
        ("Network", {"name": "LAB_NET_HQ",      "value": "10.10.0.0/16"}),
        ("Network", {"name": "LAB_NET_BRANCH1",  "value": "10.20.1.0/24"}),
        ("Network", {"name": "LAB_NET_BRANCH2",  "value": "10.20.2.0/24"}),
        ("Network", {"name": "LAB_NET_DC",       "value": "172.16.0.0/22"}),
        ("Host",    {"name": "LAB_HOST_GW_HQ",   "value": "10.10.0.1"}),
        ("Host",    {"name": "LAB_HOST_GW_DC",   "value": "172.16.0.1"}),
        ("Range",   {"name": "LAB_RANGE_MGMT",   "value": "192.168.1.100-192.168.1.199"}),
        ("Range",   {"name": "LAB_RANGE_DMZ",    "value": "10.99.0.1-10.99.0.50"}),
    ]
    objs = {}
    for obj_type, payload in specs:
        try:
            ref = create_network_object(obj_type, payload)
            objs[ref["name"]] = ref
            print(f"  [+] object: {ref['name']} ({obj_type})")
        except requests.exceptions.HTTPError as e:
            print(f"  [!] object {payload['name']}: {e.response.status_code} {e.response.text[:120]}")
    return objs


def main():
    authenticate()

    ikev2_policies = get_paginated(f"{BASE}/object/ikev2policies")
    ikev2_proposals = get_paginated(f"{BASE}/object/ikev2ipsecproposals")

    if not ikev2_policies or not ikev2_proposals:
        print("[!] No IKEv2 policies or proposals found — cannot create VPNs.")
        sys.exit(1)

    print(f"[+] {len(ikev2_policies)} IKEv2 policies, {len(ikev2_proposals)} IPSec proposals available")
    pol_by_name = {p["name"]: p["id"] for p in ikev2_policies}
    prop_by_name = {p["name"]: p["id"] for p in ikev2_proposals}

    print("\n[*] Creating named network objects...")
    objs = create_all_objects()
    print(f"[+] {len(objs)}/8 objects ready")

    ts = int(time.time())
    created = []

    # Select policies/proposals once; reuse across topologies
    pol_p2p_id = (
        pol_by_name.get("AES256")
        or pol_by_name.get("AES-256")
        or ikev2_policies[0]["id"]
    )
    prop_p2p_id = (
        prop_by_name.get("AES-256")
        or prop_by_name.get("AES256")
        or ikev2_proposals[0]["id"]
    )
    pol_hs_id = (
        pol_by_name.get("AES-GCM-NULL-SHA-LATEST")
        or pol_by_name.get("AES-GCM")
        or ikev2_policies[-1]["id"]
    )
    prop_hs_id = prop_by_name.get("AES-GCM") or ikev2_proposals[-1]["id"]
    pol_fm_id = ikev2_policies[1]["id"] if len(ikev2_policies) > 1 else ikev2_policies[0]["id"]
    prop_fm_id = ikev2_proposals[1]["id"] if len(ikev2_proposals) > 1 else ikev2_proposals[0]["id"]

    # --- VPN 1: Dual-ISP primary — P2P via ISP1, peers 203.0.113.1 (RFC 5737) ---
    name1 = f"LAB_P2P_ISP1_{ts}"
    print(f"\n[1] Creating {name1} (POINT_TO_POINT — dual-ISP primary)")
    topo1 = create_topology(name1, "POINT_TO_POINT")
    ike1_id, ipsec1_id = get_sub_ids(topo1["id"])
    if ike1_id:
        configure_ike_psk(topo1["id"], ike1_id, "LabP2P@ISP1Cisco", [pol_p2p_id])
    if ipsec1_id:
        configure_ipsec(topo1["id"], ipsec1_id, [prop_p2p_id], pfs_enabled=False, lifetime_sec=3600)
    try:
        create_endpoint(
            topo1["id"], "P2P_ISP1_Peer", "203.0.113.1", "PEER",
            protected_networks=pick_objs(objs, "LAB_NET_HQ", "LAB_HOST_GW_HQ"),
        )
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo1['id']}")
    created.append({"name": name1, "id": topo1["id"], "type": "POINT_TO_POINT"})

    # --- VPN 2: Dual-ISP backup — P2P via ISP2, peer 198.51.100.1 (RFC 5737) ---
    name2 = f"LAB_P2P_ISP2_{ts}"
    print(f"\n[2] Creating {name2} (POINT_TO_POINT — dual-ISP backup)")
    topo2 = create_topology(name2, "POINT_TO_POINT")
    ike2_id, ipsec2_id = get_sub_ids(topo2["id"])
    if ike2_id:
        configure_ike_psk(topo2["id"], ike2_id, "LabP2P@ISP2Cisco", [pol_p2p_id])
    if ipsec2_id:
        configure_ipsec(topo2["id"], ipsec2_id, [prop_p2p_id], pfs_enabled=False, lifetime_sec=3600)
    try:
        create_endpoint(
            topo2["id"], "P2P_ISP2_Peer", "198.51.100.1", "PEER",
            protected_networks=pick_objs(objs, "LAB_NET_HQ"),
        )
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo2['id']}")
    created.append({"name": name2, "id": topo2["id"], "type": "POINT_TO_POINT"})

    # --- VPN 3: Hub-and-Spoke, IKEv2 PSK, AES-GCM, PFS enabled ---
    name3 = f"LAB_HS_IKEv2_{ts}"
    print(f"\n[3] Creating {name3} (HUB_AND_SPOKE)")
    topo3 = create_topology(name3, "HUB_AND_SPOKE")
    ike3_id, ipsec3_id = get_sub_ids(topo3["id"])
    if ike3_id:
        configure_ike_psk(topo3["id"], ike3_id, "LabHS@Cisco2", [pol_hs_id])
    if ipsec3_id:
        configure_ipsec(topo3["id"], ipsec3_id, [prop_hs_id], pfs_enabled=True, lifetime_sec=7200)
    try:
        create_endpoint(
            topo3["id"], "HS_Hub", "10.200.0.1", "HUB", "ANSWER_ONLY",
            protected_networks=pick_objs(objs, "LAB_NET_DC", "LAB_HOST_GW_DC"),
        )
        create_endpoint(
            topo3["id"], "HS_Spoke1", "10.200.1.1", "SPOKE", "ORIGINATE_ONLY",
            protected_networks=pick_objs(objs, "LAB_NET_BRANCH1", "LAB_RANGE_MGMT"),
        )
        create_endpoint(
            topo3["id"], "HS_Spoke2", "10.200.2.1", "SPOKE", "ORIGINATE_ONLY",
            protected_networks=pick_objs(objs, "LAB_NET_BRANCH2", "LAB_RANGE_DMZ"),
        )
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo3['id']}")
    created.append({"name": name3, "id": topo3["id"], "type": "HUB_AND_SPOKE"})

    # --- VPN 4: Full Mesh, IKEv2 PSK, alternate policy ---
    name4 = f"LAB_FM_IKEv2_{ts}"
    print(f"\n[4] Creating {name4} (FULL_MESH)")
    topo4 = create_topology(name4, "FULL_MESH")
    ike4_id, ipsec4_id = get_sub_ids(topo4["id"])
    if ike4_id:
        configure_ike_psk(topo4["id"], ike4_id, "LabFM@Cisco3", [pol_fm_id])
    if ipsec4_id:
        configure_ipsec(topo4["id"], ipsec4_id, [prop_fm_id], pfs_enabled=True, lifetime_sec=28800)
    try:
        create_endpoint(
            topo4["id"], "FM_Site1", "192.168.200.1", "PEER",
            protected_networks=pick_objs(objs, "LAB_NET_HQ"),
        )
        create_endpoint(
            topo4["id"], "FM_Site2", "192.168.200.2", "PEER",
            protected_networks=pick_objs(objs, "LAB_NET_BRANCH1", "LAB_RANGE_DMZ"),
        )
        create_endpoint(
            topo4["id"], "FM_Site3", "192.168.200.3", "PEER",
            protected_networks=pick_objs(objs, "LAB_NET_DC"),
        )
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo4['id']}")
    created.append({"name": name4, "id": topo4["id"], "type": "FULL_MESH"})

    print(f"\n[+] Created {len(created)} VPN topologies:")
    print(json.dumps(created, indent=2))
    print("\nRun fmc_vpn_extractor.py to collect full field data.")


if __name__ == "__main__":
    main()
