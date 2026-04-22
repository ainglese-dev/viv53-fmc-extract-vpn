import datetime
import os
import tempfile
import streamlit as st

from web.extractor import run_extraction
from web.bundler import run_bundler

LAYOUT_PATH = os.path.join(os.path.dirname(__file__), "configs", "csv_layout.json")

st.set_page_config(page_title="FMC VPN Extractor", page_icon="🔒", layout="centered")
st.title("FMC S2S VPN Extractor")
st.caption("Enter your FMC credentials to extract all site-to-site VPN configurations as a CSV.")

with st.form("credentials"):
    host = st.text_input("FMC Host", placeholder="https://your-fmc.example.com")
    col1, col2 = st.columns(2)
    username = col1.text_input("Username")
    password = col2.text_input("Password", type="password")
    submitted = st.form_submit_button("Extract VPNs", type="primary", use_container_width=True)

if submitted:
    if not host or not username or not password:
        st.error("FMC Host, Username, and Password are all required.")
    else:
        st.session_state.pop("csv_bytes", None)
        st.session_state.pop("row_count", None)

        with st.status("Connecting to FMC...", expanded=True) as status:
            try:
                tmp_dir = tempfile.mkdtemp()

                def log_cb(msg):
                    st.write(msg)

                domain_dir = run_extraction(host, username, password, tmp_dir, log_cb=log_cb)
                csv_bytes, row_count = run_bundler(domain_dir, LAYOUT_PATH)

                ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
                st.session_state["csv_bytes"] = csv_bytes
                st.session_state["row_count"] = row_count
                st.session_state["csv_filename"] = f"s2s_vpns_{ts}.csv"
                status.update(label=f"Done — {row_count} tunnel row(s) ready.", state="complete")
            except RuntimeError as e:
                status.update(label="Failed", state="error")
                st.error(str(e))
            except Exception as e:
                status.update(label="Failed", state="error")
                st.error(f"Extraction failed: {e}")

if "csv_bytes" in st.session_state:
    st.download_button(
        label=f"Download CSV  ({st.session_state['row_count']} rows)",
        data=st.session_state["csv_bytes"],
        file_name=st.session_state["csv_filename"],
        mime="text/csv",
        use_container_width=True,
        type="primary",
    )
