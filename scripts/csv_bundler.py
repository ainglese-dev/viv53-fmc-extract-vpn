#!/usr/bin/env python3
"""Flatten per-topology JSON files → s2s_vpns.csv, one row per tunnel pair."""

import csv
import json
import os
from itertools import combinations

RESULTS_DIR = "./results"
OUTPUT = "./results/s2s_vpns.csv"
DEFAULT_DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
LAYOUT_PATH = "./configs/csv_layout.json"


def load_layout(path=LAYOUT_PATH):
    """Load column order and display names from the layout config.

    Returns (keys, headers): parallel lists of internal field names and CSV header strings.
    """
    with open(path) as f:
        entries = json.load(f)
    keys = [e["key"] for e in entries]
    headers = [e["header"] for e in entries]
    return keys, headers


def join(lst):
    if isinstance(lst, list):
        return ";".join(str(x) for x in lst)
    return "" if lst is None else lst


def ep_ip(ep):
    ext_info = ep.get("extranetInfo") or {}
    iface = ep.get("interface") or {}
    return ext_info.get("ipAddress") or iface.get("ipAddress") or ""


def ep_fields(ep, prefix):
    if not ep:
        return {f"{prefix}_{k}": "" for k in [
            "name", "peer_type", "ip", "extranet", "connection_type",
            "nat_traversal", "allow_incoming_ikev2_routes", "nat_exempt",
            "override_remote_vpn_filter", "dynamic_rri", "device", "interface",
        ]}
    device = ep.get("device") or {}
    iface = ep.get("interface") or {}
    return {
        f"{prefix}_name": ep.get("name", ""),
        f"{prefix}_peer_type": ep.get("peerType", ""),
        f"{prefix}_ip": ep_ip(ep),
        f"{prefix}_extranet": ep.get("extranet", ""),
        f"{prefix}_connection_type": ep.get("connectionType", ""),
        f"{prefix}_nat_traversal": ep.get("enableNatTraversal", ""),
        f"{prefix}_allow_incoming_ikev2_routes": ep.get("allowIncomingIKEv2Routes", ""),
        f"{prefix}_nat_exempt": ep.get("enableNATExempt", ""),
        f"{prefix}_override_remote_vpn_filter": ep.get("overrideRemoteVpnFilter", ""),
        f"{prefix}_dynamic_rri": ep.get("dynamicRRIEnabled", ""),
        f"{prefix}_device": device.get("name", ""),
        f"{prefix}_interface": iface.get("name", ""),
    }


def compute_pairs(topology_type, endpoints):
    """Return (local, remote) endpoint pairs representing each tunnel."""
    if not endpoints:
        return [(None, None)]
    if topology_type == "HUB_AND_SPOKE":
        hubs = [e for e in endpoints if e.get("peerType") == "HUB"]
        spokes = [e for e in endpoints if e.get("peerType") == "SPOKE"]
        hub = hubs[0] if hubs else None
        return [(hub, s) for s in spokes] if spokes else [(hub, None)]
    if topology_type == "POINT_TO_POINT":
        if len(endpoints) >= 2:
            return [(endpoints[0], endpoints[1])]
        return [(endpoints[0], None)]
    if topology_type == "FULL_MESH":
        pairs = list(combinations(endpoints, 2))
        return pairs if pairs else [(endpoints[0], None)]
    return [(ep, None) for ep in endpoints]


def flatten(topo, local_ep, remote_ep):
    ike = topo.get("ikeSettings") or {}
    ikev2 = ike.get("ikeV2Settings") or {}
    policies = ikev2.get("policies") or []
    pol = policies[0] if policies else {}

    ipsec = topo.get("ipsecSettings") or {}
    proposals = ipsec.get("ikeV2IpsecProposal") or []
    prop = proposals[0] if proposals else {}
    pfs = ipsec.get("perfectForwardSecrecy") or {}
    tfc = ipsec.get("tfcPackets") or {}

    adv = topo.get("advancedSettings") or {}
    adv_tunnel = adv.get("advancedTunnelSetting") or {}
    adv_ike = adv.get("advancedIkeSetting") or {}
    adv_ipsec = adv.get("advancedIpsecSetting") or {}
    idle = adv_tunnel.get("vpnIdleTimeout") or {}
    nat_ka = adv_tunnel.get("natKeepaliveMessageTraversal") or {}
    ike_ka = adv_ike.get("ikeKeepaliveSettings") or {}
    mtu = adv_ipsec.get("maximumTransmissionUnitAging") or {}

    row = {
        "vpn_name": topo.get("name", ""),
        "topology_type": topo.get("topologyType", ""),
        "route_based": topo.get("routeBased", ""),
        "ikev1_enabled": topo.get("ikeV1Enabled", ""),
        "ikev2_enabled": topo.get("ikeV2Enabled", ""),

        "ike_auth_type": ikev2.get("authenticationType", ""),
        "ike_psk_configured": bool(ikev2.get("manualPreSharedKey")),
        "ike_policy_name": pol.get("name", ""),
        "ike_encryption": join(pol.get("encryptionAlgorithms")),
        "ike_integrity": join(pol.get("integrityAlgorithms")),
        "ike_prf": join(pol.get("prfIntegrityAlgorithms")),
        "ike_dh_groups": join(pol.get("diffieHellmanGroups")),
        "ike_lifetime_sec": pol.get("lifetimeInSeconds", ""),
        "ike_priority": pol.get("priority", ""),

        "ipsec_proposal_name": prop.get("name", ""),
        "ipsec_encryption": join(prop.get("encryptionAlgorithms")),
        "ipsec_integrity": join(prop.get("integrityAlgorithms")),
        "ipsec_crypto_map_type": ipsec.get("cryptoMapType", ""),
        "ipsec_mode": ipsec.get("ikeV2Mode", ""),
        "ipsec_pfs_enabled": pfs.get("enabled", ""),
        "ipsec_lifetime_sec": ipsec.get("lifetimeSeconds", ""),
        "ipsec_lifetime_kb": ipsec.get("lifetimeKilobytes", ""),
        "ipsec_enable_rri": ipsec.get("enableRRI", ""),
        "ipsec_sa_strength_enforce": ipsec.get("enableSaStrengthEnforcement", ""),
        "ipsec_validate_icmp_error": ipsec.get("validateIncomingIcmpErrorMessage", ""),
        "ipsec_dnf_policy": ipsec.get("doNotFragmentPolicy", ""),
        "ipsec_tfc_enabled": tfc.get("enabled", ""),

        "adv_idle_timeout_enabled": idle.get("enabled", ""),
        "adv_idle_timeout_min": idle.get("timeoutMinutes", ""),
        "adv_nat_keepalive_enabled": nat_ka.get("enabled", ""),
        "adv_nat_keepalive_interval_sec": nat_ka.get("intervalSeconds", ""),
        "adv_bypass_access_control": adv_tunnel.get("bypassAccessControlTrafficForDecryptedTraffic", ""),
        "adv_spoke_to_spoke_through_hub": adv_tunnel.get("enableSpokeToSpokeConnectivityThroughHub", ""),

        "adv_ike_keepalive": ike_ka.get("ikeKeepalive", ""),
        "adv_ike_keepalive_threshold": ike_ka.get("threshold", ""),
        "adv_ike_keepalive_retry": ike_ka.get("retryInterval", ""),
        "adv_identity_sent": adv_ike.get("identitySentToPeer", ""),
        "adv_peer_id_validation": adv_ike.get("peerIdentityValidation", ""),
        "adv_cookie_challenge": adv_ike.get("cookieChallenge", ""),
        "adv_notify_on_disconnect": adv_ike.get("enableNotificationOnTunnelDisconnect", ""),
        "adv_aggressive_mode": adv_ike.get("enableAggressiveMode", ""),

        "adv_mtu_aging_enabled": mtu.get("enabled", ""),
        "adv_frag_before_encrypt": adv_ipsec.get("enableFragmentationBeforeEncryption", ""),
    }
    row.update(ep_fields(local_ep or {}, "local"))
    row.update(ep_fields(remote_ep or {}, "remote"))
    return row


def load_results(domain=DEFAULT_DOMAIN):
    domain_dir = f"{RESULTS_DIR}/{domain}"
    topologies = []
    for entry in sorted(os.scandir(domain_dir), key=lambda e: e.name):
        if not entry.is_file() or not entry.name.endswith(".json"):
            continue
        with open(entry.path) as f:
            topologies.append(json.load(f))
    return topologies


def main():
    keys, headers = load_layout()
    topologies = load_results()

    rows = []
    for topo in topologies:
        endpoints = topo.get("endpoints") or []
        pairs = compute_pairs(topo.get("topologyType"), endpoints)
        for local_ep, remote_ep in pairs:
            rows.append(flatten(topo, local_ep, remote_ep))

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writerow(dict(zip(keys, headers)))
        writer.writerows(rows)

    print(f"[+] Wrote {len(rows)} row(s) → {OUTPUT}")


if __name__ == "__main__":
    main()
