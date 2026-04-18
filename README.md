# FMC S2S VPN Extractor

Extracts Cisco FMC Site-to-Site VPN configurations via REST API and outputs structured JSON + flat CSV.

---

## Setup

**1. Create and activate a virtual environment**

Windows:
```bat
python -m venv .venv
.venv\Scripts\activate
```

Mac / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

---

## FMC Variables

`vpn_creator.py` and `fmc_vpn_extractor.py` prompt for these values at runtime. Press **Enter** to accept the lab defaults, or type your own:

| Variable | Description |
|---|---|
| FMC Host | Base URL of the FMC instance |
| Username | FMC login username |
| Password | FMC login password |
| Domain UUID | FMC domain to query |

---

## Run

Execute in order:

```bash
python scripts/vpn_creator.py        # seed varied VPN topologies (run once)
python scripts/fmc_vpn_extractor.py  # extract all fields → results/ (JSON per endpoint)
python scripts/csv_bundler.py        # flatten JSON → results/s2s_vpns.csv
```

---

## Output

`results/s2s_vpns.csv` — flat CSV, one row per VPN endpoint.
