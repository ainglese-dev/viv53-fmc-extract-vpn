"""PyInstaller entry point — starts Streamlit and opens the browser."""

import os
import sys
import threading
import webbrowser
import time

# Streamlit detects dev mode by checking if "site-packages" is in its __file__,
# which is never true inside a frozen bundle. Override it before import.
os.environ["STREAMLIT_GLOBAL_DEVELOPMENT_MODE"] = "false"


def _open_browser():
    time.sleep(2.5)
    webbrowser.open("http://localhost:8501")


if __name__ == "__main__":
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(base, "app.py")

    threading.Thread(target=_open_browser, daemon=True).start()

    from streamlit.web import cli as stcli

    sys.argv = [
        "streamlit", "run", app_path,
        "--browser.gatherUsageStats=false",
        "--server.headless=true",
    ]
    sys.exit(stcli.main())
