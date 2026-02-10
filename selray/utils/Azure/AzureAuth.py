import os
import json
import shutil
import subprocess
import sys
import platform
from typing import Optional, Tuple
from azure.identity import AzureCliCredential, InteractiveBrowserCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient

MGMT_SCOPE = "https://management.azure.com/.default"
ARM_RESOURCE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"


# ---------------------------
# Azure CLI helpers
# ---------------------------

def _find_az_executable() -> Optional[str]:
    az = shutil.which("az")
    if az:
        return az

    if os.name != "nt":
        candidates = [
            "/usr/bin/az",
            "/usr/local/bin/az",
            "/opt/az/bin/az",
        ]
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

    if os.name == "nt":
        try:
            cp = subprocess.run(["where.exe", "az"], capture_output=True, text=True)
            if cp.returncode == 0 and cp.stdout.strip():
                return cp.stdout.splitlines()[0].strip()
        except Exception:
            pass

    return None


def _az_installed() -> bool:
    return _find_az_executable() is not None


def _needs_sudo() -> bool:
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        return shutil.which("sudo") is not None
    return False


def _with_sudo(cmd: list[str]) -> list[str]:
    if _needs_sudo():
        return ["sudo"] + cmd
    return cmd


def _run_install_command(cmd: list[str], *, label: str) -> bool:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        if cp.returncode == 0:
            return True
        print(f"[!] Azure CLI install step failed: {label}")
        if cp.stdout:
            print(cp.stdout.strip())
        if cp.stderr:
            print(cp.stderr.strip())
        return False
    except Exception as e:
        print(f"[!] Azure CLI install step error: {label}: {e}")
        return False


def _attempt_install_az() -> bool:
    if os.name == "nt":
        if shutil.which("winget"):
            return _run_install_command(
                ["winget", "install", "-e", "--id", "Microsoft.AzureCLI",
                 "--accept-source-agreements", "--accept-package-agreements"]
                , label="winget install Microsoft.AzureCLI"
            )
        if shutil.which("choco"):
            return _run_install_command(
                ["choco", "install", "azure-cli", "-y"],
                label="choco install azure-cli",
            )
        if shutil.which("scoop"):
            return _run_install_command(
                ["scoop", "install", "azure-cli"],
                label="scoop install azure-cli",
            )
        return False

    if sys.platform == "darwin":
        if shutil.which("brew"):
            return _run_install_command(
                ["brew", "install", "azure-cli"],
                label="brew install azure-cli",
            )
        return False

    if shutil.which("curl"):
        dist_id = ""
        try:
            dist_id = (platform.freedesktop_os_release().get("ID") or "").lower()
        except Exception:
            dist_id = ""
        if dist_id == "kali":
            return _run_install_command(
                ["bash", "-c", "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash"],
                label="curl https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash",
            )
        sudo_prefix = "sudo " if _needs_sudo() else ""
        return _run_install_command(
            ["bash", "-c", f"curl -sL https://aka.ms/InstallAzureCLIDeb | {sudo_prefix}bash"],
            label="curl https://aka.ms/InstallAzureCLIDeb | bash",
        )
    if shutil.which("apt-get"):
        _run_install_command(_with_sudo(["apt-get", "update"]), label="apt-get update")
        return _run_install_command(
            _with_sudo(["apt-get", "install", "-y", "azure-cli"]),
            label="apt-get install azure-cli",
        )
    if shutil.which("dnf"):
        return _run_install_command(
            _with_sudo(["dnf", "install", "-y", "azure-cli"]),
            label="dnf install azure-cli",
        )
    if shutil.which("yum"):
        return _run_install_command(
            _with_sudo(["yum", "install", "-y", "azure-cli"]),
            label="yum install azure-cli",
        )
    if shutil.which("zypper"):
        return _run_install_command(
            _with_sudo(["zypper", "--non-interactive", "install", "azure-cli"]),
            label="zypper install azure-cli",
        )
    if shutil.which("pacman"):
        return _run_install_command(
            _with_sudo(["pacman", "-S", "--noconfirm", "azure-cli"]),
            label="pacman -S azure-cli",
        )
    return False


def ensure_az_cli_installed(*, auto_install: bool = True) -> bool:
    if _az_installed():
        return True
    if not auto_install:
        return False

    print("[!] Azure CLI not found. Attempting to install...")
    if not _attempt_install_az():
        print("[!] Azure CLI auto-install failed. Please install manually:")
        print("    https://learn.microsoft.com/cli/azure/install-azure-cli")
        return False

    if _find_az_executable():
        return True

    print("[!] Azure CLI installed but not on PATH. Restart your shell or add it to PATH.")
    return False


def make_azure_clients(subscription_id: str):
    cred, subscription_id = get_azure_context()  # your CLI->browser fallback
    return (
        cred,
        ResourceManagementClient(cred, subscription_id),
        NetworkManagementClient(cred, subscription_id),
        ComputeManagementClient(cred, subscription_id),
    )


def _run_az(cmd: list[str], *, interactive: bool = False) -> subprocess.CompletedProcess:
    """
    Run an az command.
    - interactive=False: capture output (good for parsing JSON)
    - interactive=True: attach to terminal (required for 'az login' device-code / browser flows)
    """
    az_path = _find_az_executable()
    if not az_path:
        if ensure_az_cli_installed(auto_install=True):
            az_path = _find_az_executable()
    if not az_path:
        raise FileNotFoundError("Azure CLI (az) not found for this Python process.")

    if cmd and cmd[0] == "az":
        cmd = [az_path] + cmd[1:]

    if interactive:
        # Important: DO NOT capture output, or device-code instructions won't show.
        return subprocess.run(cmd)
    else:
        return subprocess.run(cmd, capture_output=True, text=True)


def _az_account_show() -> Optional[dict]:
    cp = _run_az(["az", "account", "show", "--output", "json"])
    if cp.returncode != 0 or not (cp.stdout or "").strip():
        return None
    try:
        return json.loads(cp.stdout)
    except Exception:
        return None


def _az_can_get_arm_token() -> bool:
    cp = _run_az(
        ["az", "account", "get-access-token", "--resource", ARM_RESOURCE, "--output", "json"]
    )
    return cp.returncode == 0 and (cp.stdout or "").lstrip().startswith("{")


def ensure_az_cli_login(*, use_device_code: bool = True) -> None:
    """
    Ensures Azure CLI can acquire an ARM token (what AzureCliCredential needs).
    If not, runs an interactive az login with ARM scope.
    """
    if not ensure_az_cli_installed(auto_install=True):
        raise RuntimeError("Azure CLI is not installed or not on PATH (cannot run 'az login').")

    if _az_can_get_arm_token():
        acct = _az_account_show() or {}
        user = (acct.get("user") or {}).get("name")
        print(f"[+] Azure CLI ready for ARM token as: {user or 'unknown'}")
        return

    print("[!] Azure CLI needs login for ARM scope.")
    print("[.] Running 'az login' interactively (you will see instructions in the terminal)...")

    cmd = ["az", "login", "--scope", ARM_SCOPE]
    if use_device_code:
        cmd.insert(2, "--use-device-code")  # az login --use-device-code --scope ...

    rc = _run_az(cmd, interactive=True).returncode
    if rc != 0:
        raise RuntimeError("'az login' failed or was cancelled.")

    if not _az_can_get_arm_token():
        raise RuntimeError(
            "Login completed but still cannot acquire an ARM token.\n"
            "Try:\n"
            "  az logout\n"
            "  az login --use-device-code --scope https://management.azure.com/.default\n"
            "  az account get-access-token --resource https://management.azure.com --output json"
        )

    acct = _az_account_show() or {}
    user = (acct.get("user") or {}).get("name")
    print(f"[+] Azure CLI authenticated for ARM as: {user or 'unknown'}")


# ---------------------------
# Subscription resolution
# ---------------------------

def resolve_subscription_id(*, prompt_if_missing: bool = True) -> str:
    """
    Resolves subscription ID in this order:
      1) AZURE_SUBSCRIPTION_ID env var
      2) az account show (default subscription) if CLI logged in
      3) az account list + prompt to pick
      4) manual paste prompt
    """
    sub_id = (os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip()
    if sub_id:
        return sub_id

    acct = _az_account_show()
    if acct and acct.get("id"):
        return str(acct["id"]).strip()

    if not prompt_if_missing:
        raise RuntimeError("No subscription ID found (set AZURE_SUBSCRIPTION_ID).")

    if _az_installed():
        # If CLI installed but not logged in for ARM, prompt login so account list works.
        # (If you want to avoid this here, remove the next line.)
        if not _az_can_get_arm_token():
            ensure_az_cli_login(use_device_code=True)

        cp = _run_az(["az", "account", "list", "--output", "json"])
        if cp.returncode == 0 and (cp.stdout or "").strip():
            subs = json.loads(cp.stdout) or []
            if subs:
                print("Select a subscription:")
                for i, s in enumerate(subs, start=1):
                    print(f"  {i}) {s.get('name')} ({s.get('id')})")

                while True:
                    choice = input("Enter number: ").strip()
                    if not choice.isdigit():
                        print("Please enter a number.")
                        continue
                    idx = int(choice)
                    if 1 <= idx <= len(subs):
                        selected_id = (subs[idx - 1].get("id") or "").strip()
                        if not selected_id:
                            raise RuntimeError("Selected subscription has no id (unexpected).")

                        _run_az(["az", "account", "set", "--subscription", selected_id], interactive=True)
                        os.environ["AZURE_SUBSCRIPTION_ID"] = selected_id
                        return selected_id

                    print("Invalid selection.")

    # Manual fallback (always works)
    print("[!] Unable to discover subscription automatically.")
    manual = input("Paste your Azure Subscription ID (GUID): ").strip()
    if not manual:
        raise RuntimeError("Subscription ID was not provided.")
    os.environ["AZURE_SUBSCRIPTION_ID"] = manual
    return manual


# ---------------------------
# Credential selection
# ---------------------------

def get_credential_prefer_cli(*, prompt_cli_login: bool = True) -> object:
    """
    Prefer Azure CLI credential. If CLI isn't ready, optionally run az login,
    then retry. Fall back to InteractiveBrowserCredential if CLI is unavailable.
    """
    if not _az_installed():
        ensure_az_cli_installed(auto_install=True)

    if _az_installed():
        try:
            cli = AzureCliCredential()
            cli.get_token(MGMT_SCOPE)
            # print("[+] Authenticated using Azure CLI credentials")
            return cli
        except Exception as e:
            print(f"[!] AzureCliCredential not usable yet: {e}")

        if prompt_cli_login:
            ensure_az_cli_login(use_device_code=True)
            cli = AzureCliCredential()
            cli.get_token(MGMT_SCOPE)
            # print("[+] Authenticated using Azure CLI credentials (after az login)")
            return cli

    # Fallback: browser (note this won’t populate Azure CLI cache)
    browser = InteractiveBrowserCredential()
    browser.get_token(MGMT_SCOPE)
    print("[+] Authenticated using Interactive Browser credentials")
    return browser


def get_azure_context(*, prompt_cli_login: bool = True) -> Tuple[object, str]:
    cred = get_credential_prefer_cli(prompt_cli_login=prompt_cli_login)
    sub_id = resolve_subscription_id(prompt_if_missing=True)
    return cred, sub_id


if __name__ == "__main__":
    credential, subscription_id = get_azure_context(prompt_cli_login=True)
    print(f"Using subscription: {subscription_id}")
