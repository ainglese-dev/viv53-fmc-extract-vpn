"""Web-adapted FMC S2S VPN extractor — accepts params, no interactive prompts."""

import json
import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FMCExtractor:
    def __init__(self, host, username, password, log_cb=None):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.log = log_cb or (lambda msg: None)
        self.domain_uuid = ""
        self.base = ""
        self.session = requests.Session()
        self.session.verify = False

    def authenticate(self):
        url = f"{self.host}/api/fmc_platform/v1/auth/generatetoken"
        r = self.session.post(url, auth=(self.username, self.password))
        if r.status_code == 401:
            raise RuntimeError("Authentication failed: wrong username or password.")
        r.raise_for_status()
        self.session.headers.update({"X-auth-access-token": r.headers["X-auth-access-token"]})
        self.domain_uuid = r.headers["DOMAIN_UUID"]
        self.base = f"{self.host}/api/fmc_config/v1/domain/{self.domain_uuid}"
        self.log(f"[+] Authenticated (domain: {self.domain_uuid})")

    def get_paginated(self, url, params=None):
        params = dict(params or {})
        params.setdefault("limit", 25)
        params.setdefault("offset", 0)
        all_items = []
        while True:
            r = self.session.get(url, params=params)
            r.raise_for_status()
            data = r.json()
            all_items.extend(data.get("items", []))
            if "next" not in data.get("paging", {}):
                break
            params["offset"] += params["limit"]
        return all_items

    def get_json(self, url):
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    def enrich_ikev2_policy(self, pol_ref):
        try:
            details = self.get_json(f"{self.base}/object/ikev2policies/{pol_ref['id']}")
            pol_ref.update({
                "encryptionAlgorithms": details.get("encryptionAlgorithms", []),
                "integrityAlgorithms": details.get("integrityAlgorithms", []),
                "prfIntegrityAlgorithms": details.get("prfIntegrityAlgorithms", []),
                "diffieHellmanGroups": details.get("diffieHellmanGroups", []),
                "lifetimeInSeconds": details.get("lifetimeInSeconds"),
                "priority": details.get("priority"),
            })
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] ikev2policy {pol_ref.get('name')}: {e.response.status_code}")
        return pol_ref

    def enrich_ikev1_policy(self, pol_ref):
        try:
            details = self.get_json(f"{self.base}/object/ikev1policies/{pol_ref['id']}")
            pol_ref.update({
                "encryptionAlgorithm": details.get("encryptionAlgorithm"),
                "hashAlgorithm": details.get("hashAlgorithm"),
                "diffieHellmanGroup": details.get("diffieHellmanGroup"),
                "lifetimeInSeconds": details.get("lifetimeInSeconds"),
                "authenticationMethod": details.get("authenticationMethod"),
            })
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] ikev1policy {pol_ref.get('name')}: {e.response.status_code}")
        return pol_ref

    def enrich_ikev2_proposal(self, prop_ref):
        try:
            details = self.get_json(f"{self.base}/object/ikev2ipsecproposals/{prop_ref['id']}")
            prop_ref.update({
                "encryptionAlgorithms": details.get("encryptionAlgorithms", []),
                "integrityAlgorithms": details.get("integrityAlgorithms", []),
                "description": details.get("description", ""),
            })
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] ikev2ipsecproposal {prop_ref.get('name')}: {e.response.status_code}")
        return prop_ref

    def enrich_ikev1_proposal(self, prop_ref):
        try:
            details = self.get_json(f"{self.base}/object/ikev1ipsecproposals/{prop_ref['id']}")
            prop_ref.update({
                "encryptionAlgorithm": details.get("encryptionAlgorithm"),
                "espHashAlgorithm": details.get("espHashAlgorithm"),
            })
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] ikev1ipsecproposal {prop_ref.get('name')}: {e.response.status_code}")
        return prop_ref

    def collect_ike_settings(self, topo_id, ike_ref):
        ike_id = (ike_ref or {}).get("id")
        if not ike_id:
            return ike_ref or {}
        try:
            ike_full = self.get_json(f"{self.base}/policy/ftds2svpns/{topo_id}/ikesettings/{ike_id}")
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] ikesettings by ID: {e.response.status_code}")
            return ike_ref
        v2 = ike_full.get("ikeV2Settings", {})
        v2["policies"] = [self.enrich_ikev2_policy(p) for p in v2.get("policies", [])]
        v1 = ike_full.get("ikeV1Settings", {})
        v1["policies"] = [self.enrich_ikev1_policy(p) for p in v1.get("policies", [])]
        return ike_full

    def collect_ipsec_settings(self, ipsec):
        ipsec["ikeV2IpsecProposal"] = [
            self.enrich_ikev2_proposal(p) for p in ipsec.get("ikeV2IpsecProposal", [])
        ]
        ipsec["ikeV1IpsecProposal"] = [
            self.enrich_ikev1_proposal(p) for p in ipsec.get("ikeV1IpsecProposal", [])
        ]
        return ipsec

    def collect_endpoints(self, topo_id):
        try:
            ep_refs = self.get_paginated(f"{self.base}/policy/ftds2svpns/{topo_id}/endpoints")
        except requests.exceptions.HTTPError as e:
            self.log(f"     [!] endpoints list: {e.response.status_code}")
            return []
        full_endpoints = []
        for ep_ref in ep_refs:
            ep_id = ep_ref.get("id")
            if not ep_id:
                full_endpoints.append(ep_ref)
                continue
            try:
                ep_full = self.get_json(f"{self.base}/policy/ftds2svpns/{topo_id}/endpoints/{ep_id}")
                ep_full.pop("metadata", None)
                ep_full.pop("links", None)
                full_endpoints.append(ep_full)
            except requests.exceptions.HTTPError as e:
                self.log(f"     [!] endpoint {ep_ref.get('name')}: {e.response.status_code}")
                full_endpoints.append(ep_ref)
        return full_endpoints

    def run(self, output_dir):
        self.authenticate()
        domain_dir = os.path.join(output_dir, self.domain_uuid)
        os.makedirs(domain_dir, exist_ok=True)

        topologies = self.get_paginated(
            f"{self.base}/policy/ftds2svpns",
            {"expanded": "true", "limit": 25},
        )
        self.log(f"[+] Found {len(topologies)} S2S VPN topology/ies")

        for topo in topologies:
            topo_id = topo["id"]
            topo_name = topo.get("name", "unknown")
            self.log(f"  -> {topo_name} ({topo.get('topologyType', '?')})")

            record = {
                "name": topo_name,
                "id": topo_id,
                "type": topo.get("type"),
                "topologyType": topo.get("topologyType"),
                "routeBased": topo.get("routeBased"),
                "ikeV1Enabled": topo.get("ikeV1Enabled"),
                "ikeV2Enabled": topo.get("ikeV2Enabled"),
                "metadata": topo.get("metadata"),
                "ikeSettings": self.collect_ike_settings(topo_id, topo.get("ikeSettings")),
                "ipsecSettings": self.collect_ipsec_settings(topo.get("ipsecSettings", {})),
                "advancedSettings": topo.get("advancedSettings", {}),
                "endpoints": self.collect_endpoints(topo_id),
            }
            out_path = os.path.join(domain_dir, f"{topo_id}.json")
            with open(out_path, "w") as f:
                json.dump(record, f, indent=2)
            self.log(f"     saved {topo_id}.json")

        self.log(f"[+] Extraction complete — {len(topologies)} topology/ies")
        return domain_dir


def run_extraction(host, username, password, output_dir, log_cb=None):
    return FMCExtractor(host, username, password, log_cb=log_cb).run(output_dir)
