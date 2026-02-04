import secrets
import string
import time
from typing import Optional, Tuple
from .AzureAuth import get_azure_context, make_azure_clients
from azure.core.exceptions import HttpResponseError


def _rand_suffix(n: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def rotate_public_ip(
    network_client,
    compute_client,
    resource_group: str,
    location: str,
    vm_name: str,
    nic_name: str,
    *,
    delete_old_public_ip: bool = True,
    restart_vm: bool = False,
    ipconfig_name: Optional[str] = None,   # if None, uses first ipconfig
    new_pip_name: Optional[str] = None,    # optionally supply your own name
    sku_name: str = "Standard",
    allocation_method: str = "Static",
    assign_ip_timeout: int = 120,
) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Rotates the VM's public IP by:
      1) creating a new Public IP resource
      2) attaching it to the NIC ipconfig
      3) (optionally) restarting the VM
      4) (optionally) deleting the old Public IP resource

    Returns:
      (new_public_ip, new_pip_resource_name, old_public_ip, old_pip_resource_name)

    Notes:
    - Azure will assign the new public IP from its pool; you can't pick arbitrary addresses.
    - restart_vm=False is usually fine; restart only helps flush existing connections.
    - delete_old_public_ip=True will delete the previous Public IP resource (after it is detached).
    """

    # Get NIC and determine old public IP (if any)
    nic = network_client.network_interfaces.get(resource_group, nic_name)
    if not nic.ip_configurations:
        raise RuntimeError("NIC has no ip_configurations; cannot rotate public IP.")

    if ipconfig_name:
        matches = [c for c in nic.ip_configurations if c.name == ipconfig_name]
        if not matches:
            raise RuntimeError(f"ipconfig_name '{ipconfig_name}' not found on NIC.")
        ipcfg = matches[0]
    else:
        ipcfg = nic.ip_configurations[0]

    old_pip_id = None
    old_pip_name = None
    old_ip = None

    # ipcfg.public_ip_address may be an object with .id or a dict depending on SDK
    if getattr(ipcfg, "public_ip_address", None) is not None:
        old_pip_id = getattr(ipcfg.public_ip_address, "id", None) or (
            ipcfg.public_ip_address.get("id") if isinstance(ipcfg.public_ip_address, dict) else None
        )

    if old_pip_id:
        # Resource ID ends with ".../publicIPAddresses/<name>"
        old_pip_name = old_pip_id.split("/")[-1]
        try:
            old_pip_obj = network_client.public_ip_addresses.get(resource_group, old_pip_name)
            old_ip = getattr(old_pip_obj, "ip_address", None)
        except Exception:
            # Not fatal; we can still proceed
            pass

    # Create new Public IP
    pip_name = new_pip_name or f"pip-proxy-rot-{_rand_suffix()}"
    try:
        new_pip = network_client.public_ip_addresses.begin_create_or_update(
            resource_group,
            pip_name,
            {
                "location": location,
                "public_ip_allocation_method": allocation_method,
                "sku": {"name": sku_name},
            },
        ).result()
    except HttpResponseError as e:
        raise RuntimeError(f"Failed to create new Public IP resource: {e}") from e

    # Attach new Public IP to NIC
    ipcfg.public_ip_address = {"id": new_pip.id}
    try:
        network_client.network_interfaces.begin_create_or_update(
            resource_group, nic_name, nic
        ).result()
    except HttpResponseError as e:
        raise RuntimeError(f"Failed to update NIC with new Public IP: {e}") from e

    # Optional VM restart (usually not required)
    if restart_vm:
        try:
            compute_client.virtual_machines.begin_restart(resource_group, vm_name).result()
        except HttpResponseError as e:
            raise RuntimeError(f"Failed to restart VM after IP rotation: {e}") from e

    # Wait briefly for the new IP address field to be populated (just to return it)
    deadline = time.time() + assign_ip_timeout
    new_ip = None
    while time.time() < deadline:
        pip_obj = network_client.public_ip_addresses.get(resource_group, pip_name)
        new_ip = getattr(pip_obj, "ip_address", None)
        if new_ip:
            break
        time.sleep(2)

    if not new_ip:
        # Not fatal for the rotation itself, but caller probably wants it
        raise RuntimeError("Timed out waiting for Azure to report the newly assigned public IP address.")

    # Delete old Public IP (now detached)
    if delete_old_public_ip and old_pip_name:
        try:
            network_client.public_ip_addresses.begin_delete(resource_group, old_pip_name).result()
        except HttpResponseError as e:
            # Don't hide the new IP rotation success; surface a warning
            print(f"[!] Rotated to new IP {new_ip}, but failed to delete old Public IP '{old_pip_name}': {e}")

    return new_ip, pip_name, old_ip, old_pip_name

def rotate_ip_if_needed(resource_group,
                        vm_name,
                        attempts_before_rotating=5,
                        current_attempt = 0,
                        network_client = None,
                        compute_client = None,
                        nic_name = None,
                        location = "eastus"):

    print(current_attempt)

    if not network_client or not compute_client:
        credential, subscription_id = get_azure_context()
        cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    if current_attempt < attempts_before_rotating:
        return current_attempt + 1, None, None, None

    new_ip, new_pip_name, old_ip, old_pip_name = rotate_public_ip(
        network_client=network_client,
        compute_client=compute_client,
        resource_group=resource_group,
        location=location,
        vm_name=vm_name,
        nic_name=nic_name,
        delete_old_public_ip=True,
        restart_vm=False,
    )

    new_url = f"http://{new_ip}:3128"

    return 0, new_ip, new_url, new_pip_name
