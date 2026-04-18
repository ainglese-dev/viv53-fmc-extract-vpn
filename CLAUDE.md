# CLAUDE.md

## Project Overview
Cisco FMC S2S VPN configuration extractor for a shared lab environment. Chains FMC REST API calls to collect all classic manual VPN fields, outputs structured JSON, then flattens to CSV (one row per endpoint) for auditing and analysis.

## Lab Environment
- **FMC**: `https://fmcrestapisandbox.cisco.com`
- **Username**: `angeling`
- **Password**: `UR_CVk4K^b36dp6i`
- **Domain UUID**: `e276abec-e0f2-11e3-8169-6d9ed49b625f`
- SSL verification is disabled (`verify=False`) — lab only, shared sandbox.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/vpn_creator.py` | Create varied VPN topologies in FMC lab for test data coverage |
| `scripts/fmc_vpn_extractor.py` | Extract all S2S VPN fields → `results/s2s_vpns_full.json` |
| `scripts/csv_bundler.py` | Flatten JSON → `results/s2s_vpns.csv` (one row per endpoint) |

### Recommended execution order

```bash
source .venv/bin/activate
python scripts/vpn_creator.py        # seed varied VPNs (run once)
python scripts/fmc_vpn_extractor.py  # extract all fields to JSON
python scripts/csv_bundler.py        # produce CSV from JSON
```

All scripts prompt for credentials with lab defaults pre-filled — press Enter to accept.

## Output Files

```
results/
  {domain_uuid}/
    {ep_uuid}.json     ← one file per endpoint, self-contained (topology context + endpoint data)
    {topo_uuid}.json   ← one file for topologies with zero endpoints
  s2s_vpns.csv         ← flat CSV produced by csv_bundler.py (one row per file = one row per endpoint)
```

Files are written one per endpoint as extraction completes — a crash mid-run leaves already-saved files intact. Re-runs overwrite in place (idempotent).

## FMC API Conventions

- Auth: `POST /api/fmc_platform/v1/auth/generatetoken` → `X-auth-access-token` header
- Base: `/api/fmc_config/v1/domain/{domain_uuid}`
- S2S VPNs: `.../policy/ftds2svpns` (use `?expanded=true` for embedded ipsecSettings/advancedSettings)
- **List endpoints return reference objects only** — always fetch sub-resources by ID for full data:
  - `GET .../ikesettings/{id}` → full IKE data including `ikeV2Settings` (auth type, PSK, policy refs)
  - `GET /object/ikev2policies/{id}` → encryption, integrity, PRF, DH groups, lifetime
  - `GET /object/ikev2ipsecproposals/{id}` → encryption, integrity algorithms
  - `GET .../endpoints/{id}` → peer IP, peerType, connectionType, NAT settings

## Data Model Notes

- `ikeSettings` in the expanded topology list is a reference only `{id, type, links}` — must GET by ID
- `ipsecSettings` and `advancedSettings` are already full objects in the expanded list
- Extranet endpoints use `extranetInfo.ipAddress` as the peer IP (no FTD device reference)
- For device-attached (non-extranet) endpoints, `device.name` and `interface.name` carry the device info
