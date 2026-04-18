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


def create_endpoint(topo_id, name, ip, peer_type, connection_type="BIDIRECTIONAL"):
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
        "protectedNetworks": {},
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

    ts = int(time.time())
    created = []

    # --- VPN 1: Point-to-Point, IKEv2 PSK, first available policy ---
    name1 = f"LAB_P2P_IKEv2_{ts}"
    print(f"\n[1] Creating {name1} (POINT_TO_POINT)")
    topo1 = create_topology(name1, "POINT_TO_POINT")
    ike1_id, ipsec1_id = get_sub_ids(topo1["id"])
    pol1_id = (
        pol_by_name.get("AES256")
        or pol_by_name.get("AES-256")
        or ikev2_policies[0]["id"]
    )
    prop1_id = (
        prop_by_name.get("AES-256")
        or prop_by_name.get("AES256")
        or ikev2_proposals[0]["id"]
    )
    if ike1_id:
        configure_ike_psk(topo1["id"], ike1_id, "LabP2P@Cisco1", [pol1_id])
    if ipsec1_id:
        configure_ipsec(topo1["id"], ipsec1_id, [prop1_id], pfs_enabled=False, lifetime_sec=3600)
    # P2P topology allows only one extranet endpoint; the other must be a managed FTD device.
    try:
        create_endpoint(topo1["id"], "P2P_RemotePeer", "172.16.10.1", "PEER")
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo1['id']}")
    created.append({"name": name1, "id": topo1["id"], "type": "POINT_TO_POINT"})

    # --- VPN 2: Hub-and-Spoke, IKEv2 PSK, AES-GCM, PFS enabled ---
    name2 = f"LAB_HS_IKEv2_{ts}"
    print(f"\n[2] Creating {name2} (HUB_AND_SPOKE)")
    topo2 = create_topology(name2, "HUB_AND_SPOKE")
    ike2_id, ipsec2_id = get_sub_ids(topo2["id"])
    pol2_id = (
        pol_by_name.get("AES-GCM-NULL-SHA-LATEST")
        or pol_by_name.get("AES-GCM")
        or ikev2_policies[-1]["id"]
    )
    prop2_id = prop_by_name.get("AES-GCM") or ikev2_proposals[-1]["id"]
    if ike2_id:
        configure_ike_psk(topo2["id"], ike2_id, "LabHS@Cisco2", [pol2_id])
    if ipsec2_id:
        configure_ipsec(topo2["id"], ipsec2_id, [prop2_id], pfs_enabled=True, lifetime_sec=7200)
    try:
        create_endpoint(topo2["id"], "HS_Hub", "10.200.0.1", "HUB", "ANSWER_ONLY")
        create_endpoint(topo2["id"], "HS_Spoke1", "10.200.1.1", "SPOKE", "ORIGINATE_ONLY")
        create_endpoint(topo2["id"], "HS_Spoke2", "10.200.2.1", "SPOKE", "ORIGINATE_ONLY")
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo2['id']}")
    created.append({"name": name2, "id": topo2["id"], "type": "HUB_AND_SPOKE"})

    # --- VPN 3: Full Mesh, IKEv2 PSK, alternate policy ---
    name3 = f"LAB_FM_IKEv2_{ts}"
    print(f"\n[3] Creating {name3} (FULL_MESH)")
    topo3 = create_topology(name3, "FULL_MESH")
    ike3_id, ipsec3_id = get_sub_ids(topo3["id"])
    pol3_id = ikev2_policies[1]["id"] if len(ikev2_policies) > 1 else ikev2_policies[0]["id"]
    prop3_id = ikev2_proposals[1]["id"] if len(ikev2_proposals) > 1 else ikev2_proposals[0]["id"]
    if ike3_id:
        configure_ike_psk(topo3["id"], ike3_id, "LabFM@Cisco3", [pol3_id])
    if ipsec3_id:
        configure_ipsec(topo3["id"], ipsec3_id, [prop3_id], pfs_enabled=True, lifetime_sec=28800)
    try:
        create_endpoint(topo3["id"], "FM_Site1", "192.168.200.1", "PEER")
        create_endpoint(topo3["id"], "FM_Site2", "192.168.200.2", "PEER")
        create_endpoint(topo3["id"], "FM_Site3", "192.168.200.3", "PEER")
    except requests.exceptions.HTTPError as e:
        print(f"  [!] endpoint creation: {e.response.status_code} {e.response.text[:200]}")
    print(f"  [+] ID: {topo3['id']}")
    created.append({"name": name3, "id": topo3["id"], "type": "FULL_MESH"})

    print(f"\n[+] Created {len(created)} VPN topologies:")
    print(json.dumps(created, indent=2))
    print("\nRun fmc_vpn_extractor.py to collect full field data.")


if __name__ == "__main__":
    main()
