# PRD: FMC S2S VPN Configuration Extractor

## Goal

Programmatically extract all classic manual configuration fields for Site-to-Site VPNs from Cisco Firepower Management Center (FMC) via REST API. Produce a complete nested JSON, then flatten to CSV for auditing, documentation, or downstream tooling.

## Background

FMC stores S2S VPN config across multiple nested API resources: topology, IKE settings, IPSec settings, advanced settings, and per-endpoint data. Manually collecting these fields from the UI is time-consuming and error-prone. The list-level API endpoints return only reference objects — enrichment requires per-ID sub-calls and separate object lookups for policies and proposals.

## Target Data — Classic Manual Fields

### Topology
- Name, topology type (POINT_TO_POINT / HUB_AND_SPOKE / FULL_MESH), route-based flag
- IKEv1 enabled, IKEv2 enabled

### IKE Settings
- Authentication type (MANUAL_PRE_SHARED_KEY / CERTIFICATE)
- PSK presence indicator (not value in CSV)
- IKEv2 policy: encryption algorithms, integrity algorithms, PRF algorithms, DH groups, lifetime (seconds), priority
- IKEv1 policy (if enabled): encryption, hash, DH group, auth method, lifetime

### IPSec Settings
- Crypto map type (STATIC / DYNAMIC), mode (TUNNEL / TRANSPORT)
- IKEv2 IPSec proposals: name, encryption algorithms, integrity algorithms
- Perfect Forward Secrecy (enabled flag)
- SA lifetimes (seconds, kilobytes)
- Reverse Route Injection (RRI)
- SA strength enforcement, ICMP error validation, Do-Not-Fragment policy
- TFC packets (dummy traffic) settings

### Advanced Settings
- IKE keepalive (enabled, threshold, retry interval)
- Aggressive mode, identity sent to peer, peer identity validation
- Cookie challenge settings, notification on tunnel disconnect
- VPN idle timeout (enabled, minutes)
- NAT keepalive (enabled, interval seconds)
- Bypass access control for decrypted traffic
- Spoke-to-spoke connectivity through hub
- Fragmentation before encryption, MTU aging

### Per-Endpoint Fields
- Name, peer type (HUB / SPOKE / PEER)
- Peer IP address (extranetInfo.ipAddress), dynamic IP flag
- Extranet flag
- Connection type (BIDIRECTIONAL / ORIGINATE_ONLY / ANSWER_ONLY)
- NAT traversal, NAT exempt
- Allow incoming IKEv2 routes
- Override remote VPN filter, dynamic RRI
- Protected networks (if configured)
- Device name and interface (for device-attached, non-extranet endpoints)

## Scripts

### `scripts/vpn_creator.py`
Creates 3 varied VPN topologies in the FMC lab for data coverage:
1. **Point-to-Point** — IKEv2, PSK, first available AES-256 policy, 2 PEER endpoints
2. **Hub-and-Spoke** — IKEv2, PSK, AES-GCM policy, PFS enabled, 1 HUB + 1 SPOKE endpoint
3. **Full Mesh** — IKEv2, PSK, alternate policy, 2 PEER endpoints

Dynamically reads available IKEv2 policies and proposals before creating. Names are timestamped to avoid collisions in the shared sandbox.

### `scripts/fmc_vpn_extractor.py`
1. Authenticates via token
2. Fetches all S2S VPN topologies with `expanded=true` (gets full ipsecSettings and advancedSettings inline)
3. For each topology, creates `results/{topo_uuid}/` and saves incrementally:
   - `topology.json` — base fields written first
   - Fetches full `ikeSettings` by ID → saves `ike_settings.json`
   - For each IKEv2 policy reference: fetches `/object/ikev2policies/{id}` for algorithms and lifetime
   - For each IPSec proposal reference: fetches `/object/ikev2ipsecproposals/{id}` for algorithms → saves `ipsec_settings.json`
   - Saves `advanced_settings.json` (already full from expanded list)
   - Fetches endpoint list, enriches each by ID → saves `endpoints/{ep_uuid}.json`
4. Re-runs overwrite in place; a crash leaves previously completed topology dirs intact

### `scripts/csv_bundler.py`
1. Walks `results/` for UUID subdirectories, loads `topology.json`, `ike_settings.json`, `ipsec_settings.json`, `advanced_settings.json`, and all `endpoints/*.json`
2. Emits one CSV row per endpoint (topology fields repeated per row)
3. VPNs with zero endpoints get one row with empty endpoint columns
4. Saves to `results/s2s_vpns.csv`

## CSV Schema (one row per endpoint)

| Column | FMC Source |
|---|---|
| vpn_name | topology.name |
| topology_type | topology.topologyType |
| route_based | topology.routeBased |
| ikev1_enabled / ikev2_enabled | topology flags |
| ike_auth_type | ikeSettings.ikeV2Settings.authenticationType |
| ike_psk_configured | bool(manualPreSharedKey present) |
| ike_policy_name | ikeV2Settings.policies[0].name |
| ike_encryption | ikev2policies.encryptionAlgorithms (semicolon-joined) |
| ike_integrity | ikev2policies.integrityAlgorithms |
| ike_prf | ikev2policies.prfIntegrityAlgorithms |
| ike_dh_groups | ikev2policies.diffieHellmanGroups |
| ike_lifetime_sec | ikev2policies.lifetimeInSeconds |
| ipsec_proposal_name | ikeV2IpsecProposal[0].name |
| ipsec_encryption | ikev2ipsecproposals.encryptionAlgorithms |
| ipsec_integrity | ikev2ipsecproposals.integrityAlgorithms |
| ipsec_crypto_map_type | ipsecSettings.cryptoMapType |
| ipsec_mode | ipsecSettings.ikeV2Mode |
| ipsec_pfs_enabled | perfectForwardSecrecy.enabled |
| ipsec_lifetime_sec / _kb | ipsecSettings lifetimes |
| ipsec_enable_rri | ipsecSettings.enableRRI |
| adv_idle_timeout_* | advancedTunnelSetting.vpnIdleTimeout |
| adv_nat_keepalive_* | natKeepaliveMessageTraversal |
| adv_ike_keepalive_* | advancedIkeSetting.ikeKeepaliveSettings |
| adv_identity_sent | identitySentToPeer |
| adv_peer_id_validation | peerIdentityValidation |
| endpoint_name | endpoint.name |
| endpoint_peer_type | endpoint.peerType |
| endpoint_ip | endpoint.extranetInfo.ipAddress |
| endpoint_connection_type | endpoint.connectionType |
| endpoint_nat_traversal | endpoint.enableNatTraversal |
| endpoint_allow_incoming_ikev2_routes | endpoint.allowIncomingIKEv2Routes |

## Success Criteria

1. `s2s_vpns_full.json` has no empty `ikeSettings` objects — all `ikeV2Settings` fields populated for configured VPNs
2. All endpoints have `endpoint_ip`, `endpoint_peer_type`, and `endpoint_connection_type`
3. CSV has one row per endpoint; no blank IKE/IPSec columns for well-configured VPNs
4. All three topology types (P2P, HUB_AND_SPOKE, FULL_MESH) present in output data
