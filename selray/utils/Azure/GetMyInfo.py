import urllib.request
import getpass
import socket
import uuid
import subprocess
import json

def get_public_ip() -> str:
    """
    Returns your current public IPv4 address as a string.
    Raises RuntimeError on failure.
    """
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            ip = resp.read().decode("utf-8").strip()
            return ip
    except Exception as e:
        raise RuntimeError(f"Failed to determine public IP: {e}")


def get_owner_fingerprint() -> str:
    """
    Returns a stable owner identifier in the form:
        username-hostname-macaddress

    Works on Linux, Windows, macOS.

    MAC address is normalized and stripped of separators for tag safety.
    """
    username = getpass.getuser()
    hostname = socket.gethostname()

    # uuid.getnode() returns a 48-bit MAC if available
    mac_int = uuid.getnode()

    # Detect random MACs (locally administered bit set)
    if (mac_int >> 40) & 0x02:
        mac = "unknownmac"
    else:
        mac = f"{mac_int:012x}"

    return f"{username}-{hostname}-{mac}"

def get_azure_user_id_from_cli() -> str | None:
    try:
        result = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)

        user = data.get("user", {})
        return user.get("name")  # usually UPN/email

    except Exception:
        return None

def get_user():
    return (
        get_azure_user_id_from_cli()     # best if available
        or get_owner_fingerprint()          # OS-level user
        or "unknown"
    )