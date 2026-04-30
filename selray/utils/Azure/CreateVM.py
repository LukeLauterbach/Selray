from .AzureAuth import get_azure_context, make_azure_clients
from .CheckProxy import wait_for_proxy_ready
from .GetMyInfo import get_public_ip, get_user
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
import os
import time
from random import randint
from string import ascii_lowercase,digits
from secrets import choice
import re
from datetime import datetime

LOCATION = os.environ.get("AZURE_LOCATION", "eastus")


def _debug(debug_enabled: bool, message: str) -> None:
    if not debug_enabled:
        return
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - DEBUG: {message}")


def _azure_error_code(exc: Exception) -> str:
    err = getattr(exc, "error", None)
    code = getattr(err, "code", None) or getattr(exc, "code", None)
    return str(code or "").strip()


def _is_os_provisioning_timeout(exc: Exception) -> bool:
    code = _azure_error_code(exc)
    if code == "OSProvisioningTimedOut":
        return True
    return "OSProvisioningTimedOut" in str(exc)


def _is_capacity_or_region_full_error(exc: Exception) -> bool:
    code = _azure_error_code(exc)
    if code in {
        "SkuNotAvailable",
        "AllocationFailed",
        "ZonalAllocationFailed",
        "OverconstrainedAllocationRequest",
        "OperationNotAllowed",
    }:
        return True

    msg = str(exc).lower()
    patterns = (
        "insufficient capacity",
        "not enough capacity",
        "allocation failed",
        "sku is currently not available",
        "overconstrained",
        "zone does not have enough capacity",
    )
    return any(p in msg for p in patterns)


def ensure_rg(resource_client: ResourceManagementClient, resource_group_name, location: str = LOCATION) -> None:
    """
    Try to create/update the resource group if permissions allow.
    Always verify it exists afterward; if it doesn't, raise a fatal error.
    """
    if not str(resource_group_name or "").strip():
        raise RuntimeError(
            "Azure resource group is empty. Pass --azure-resource-group or set AZURE_RG."
        )

    create_error: Exception | None = None
    try:
        resource_client.resource_groups.create_or_update(
            resource_group_name, {"location": location}
        )
    except HttpResponseError as exc:
        # Likely permission issue; we'll verify existence below.
        create_error = exc

    try:
        resource_client.resource_groups.get(resource_group_name)
    except (ResourceNotFoundError, HttpResponseError) as exc:
        raise RuntimeError(
            f"Resource group '{resource_group_name}' does not exist or is not accessible. "
            "Use an existing resource group you have access to (set AZURE_RG)."
        ) from exc

    if create_error is not None:
        # RG exists but create/update was not permitted; continue silently.
        pass


def rand_suffix(n: int = 6) -> str:
    alphabet = ascii_lowercase + digits
    return "".join(choice(alphabet) for _ in range(n))

def sanitize_vm_name(name: str, max_len: int = 80) -> str:
    # Azure VM names allow word chars plus '.', '-', '_' and must start/end with a word char.
    allowed = re.compile(r"[^A-Za-z0-9_.-]")
    cleaned = allowed.sub("-", name).strip()
    if not cleaned or not re.match(r"^[A-Za-z0-9_]", cleaned):
        cleaned = f"s{cleaned}"
    if max_len > 0 and len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    cleaned = re.sub(r"[^A-Za-z0-9_]+$", "", cleaned)
    if not cleaned:
        cleaned = "selray"
    return cleaned


def create_networking(network_client: NetworkManagementClient, resource_group, location: str = LOCATION, debug: bool = False):
    suffix = rand_suffix()

    vnet_name = f"vnet-proxy-{suffix}"
    subnet_name = "subnet-proxy"
    nsg_name = f"nsg-proxy-{suffix}"
    pip_name = f"pip-proxy-{suffix}"
    nic_name = f"nic-proxy-{suffix}"

    _debug(debug, f"Creating virtual network '{vnet_name}' in resource group '{resource_group}'")
    network_client.virtual_networks.begin_create_or_update(
        resource_group,
        vnet_name,
        {
            "location": location,
            "address_space": {"address_prefixes": ["10.10.0.0/16"]},
            "subnets": [{"name": subnet_name, "address_prefix": "10.10.1.0/24"}],
        },
    ).result()

    subnet = network_client.subnets.get(resource_group, vnet_name, subnet_name)

    _debug(debug, f"Creating network security group '{nsg_name}' and proxy allow rule")
    nsg = network_client.network_security_groups.begin_create_or_update(
        resource_group,
        nsg_name,
        {"location": location},
    ).result()

    # Allow Squid ONLY from your public IP
    network_client.security_rules.begin_create_or_update(
        resource_group,
        nsg_name,
        "Allow-Proxy-From-MyIP",
        {
            "protocol": "Tcp",
            "source_address_prefix": get_public_ip() + "/32",
            "source_port_range": "*",
            "destination_address_prefix": "*",
            "destination_port_range": "3128",
            "access": "Allow",
            "priority": 100,
            "direction": "Inbound",
        },
    ).result()

    # No SSH rule created. Inbound 22 will not be allowed.

    _debug(debug, f"Creating public IP resource '{pip_name}'")
    pip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group,
        pip_name,
        {
            "location": location,
            "public_ip_allocation_method": "Static",
            "sku": {"name": "Standard"},
        },
    ).result()

    _debug(debug, f"Creating network interface '{nic_name}'")
    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group,
        nic_name,
        {
            "location": location,
            "ip_configurations": [
                {
                    "name": "ipconfig1",
                    "subnet": {"id": subnet.id},
                    "public_ip_address": {"id": pip.id},
                }
            ],
            "network_security_group": {"id": nsg.id},
        },
    ).result()

    _debug(debug, f"Created networking resources: nic_id='{nic.id}', pip_id='{pip.id}'")
    return nic.id, nic_name, pip.id, nsg.id, pip_name


def b64(s: str) -> str:
    from base64 import b64encode
    return b64encode(s.encode("utf-8")).decode("utf-8")


def cloud_init_squid(port: int, allowed_src_cidr: str) -> str:
    # Squid enforces the allowed source at the app layer too.
    # NSG also enforces it at the network edge.
    #
    # Optionally disables SSH service on the VM.
    return f"""#cloud-config
package_update: true
packages:
  - squid
write_files:
  - path: /etc/squid/squid.conf
    permissions: '0644'
    content: |
      http_port {port}
      via off
      forwarded_for delete

      acl allowed_src src {allowed_src_cidr}
      http_access allow allowed_src
      http_access deny all

runcmd:
  - systemctl enable squid
  - systemctl restart squid

  # Disable SSH service completely (best effort)
  - systemctl stop ssh || true
  - systemctl disable ssh || true
  - systemctl stop sshd || true
  - systemctl disable sshd || true
"""


def create_vm(resource_group, compute_client: ComputeManagementClient, nic_id: str, owner="defaultUser", vm_name="", location: str = LOCATION, debug: bool = False) -> None:
    user_data = b64(cloud_init_squid(3128, get_public_ip() + "/32"))
    admin_username = os.environ.get("AZURE_ADMIN_USER", "azureuser")

    # We don't actually care about saving this, it just needs to be generated.
    admin_ssh_public_key = os.environ.get("AZURE_SSH_PUBKEY", "<PASTE_YOUR_SSH_PUBLIC_KEY>")
    if "<PASTE_YOUR_SSH_PUBLIC_KEY>" in admin_ssh_public_key:
        from .SSHKeyGen import generate_ed25519_openssh_keypair
        _, admin_ssh_public_key = generate_ed25519_openssh_keypair()

    image_ref = {
        "publisher": "Canonical",
        "offer": "ubuntu-24_04-lts",
        "sku": "server",
        "version": "latest",
    }

    vm_params = {
        "location": location,

        # Tags live at the top-level for VM resources.
        "tags": {
            "owner": owner,
            "purpose": "selray",
            "project": "proxy-rotation",
        },

        # Use ARM-style field names when passing raw dict payloads.
        "hardwareProfile": {"vmSize": os.environ.get("AZURE_VM_SIZE", "Standard_B1s")},
        "storageProfile": {"imageReference": image_ref},
        "osProfile": {
            "computerName": vm_name,
            "adminUsername": admin_username,
            "linuxConfiguration": {
                "disablePasswordAuthentication": True,
                "ssh": {
                    "publicKeys": [
                        {
                            "path": f"/home/{admin_username}/.ssh/authorized_keys",
                            "keyData": admin_ssh_public_key,
                        }
                    ]
                },
            },
        },
        "networkProfile": {
            "networkInterfaces": [
                {"id": nic_id, "primary": True}
            ]
        },
        "userData": user_data,
    }
    _debug(debug, f"VM create request details: location='{location}', vm_size='{vm_params['hardwareProfile']['vmSize']}'")
    vm_size = vm_params["hardwareProfile"]["vmSize"]

    _debug(debug, f"Creating VM '{vm_name}' in resource group '{resource_group}'")
    try:
        poller = compute_client.virtual_machines.begin_create_or_update(
            resource_group, vm_name, vm_params
        )
    except HttpResponseError as exc:
        if _is_capacity_or_region_full_error(exc):
            raise RuntimeError(
                f"Azure capacity issue creating VM '{vm_name}' in region '{location}' with size '{vm_size}'. "
                "Try switching regions (set AZURE_LOCATION) or choose a different VM size (set AZURE_VM_SIZE)."
            ) from exc
        raise

    # VM creation is a long-running operation. Emit periodic status so it doesn't look hung.
    vm_create_timeout_s = int(os.environ.get("AZURE_VM_CREATE_TIMEOUT", "1800"))
    poll_interval_s = int(os.environ.get("AZURE_VM_CREATE_POLL_INTERVAL", "10"))
    started = time.time()
    while not poller.done():
        elapsed = int(time.time() - started)
        if elapsed > vm_create_timeout_s:
            raise TimeoutError(
                f"Timed out after {vm_create_timeout_s}s waiting for VM '{vm_name}' provisioning."
            )
        provider_state = "unknown"
        try:
            vm = compute_client.virtual_machines.get(resource_group, vm_name)
            provider_state = getattr(vm, "provisioning_state", "unknown")
        except Exception:
            provider_state = "not-visible-yet"
        _debug(
            debug,
            f"VM '{vm_name}' provisioning in progress (elapsed={elapsed}s, sdk_status={poller.status()}, provider_state={provider_state})"
        )
        time.sleep(max(1, poll_interval_s))

    try:
        poller.result()
        _debug(debug, f"VM '{vm_name}' provisioning completed")
    except HttpResponseError as exc:
        if _is_capacity_or_region_full_error(exc):
            raise RuntimeError(
                f"Azure capacity issue while provisioning VM '{vm_name}' in region '{location}' with size '{vm_size}'. "
                "Try switching regions (set AZURE_LOCATION) or choose a different VM size (set AZURE_VM_SIZE)."
            ) from exc
        if not _is_os_provisioning_timeout(exc):
            raise
        # Azure can return OSProvisioningTimedOut even when the VM later reaches a usable state.
        print(
            f"[!] Azure returned OSProvisioningTimedOut for VM '{vm_name}'. "
            "Continuing and waiting for proxy readiness."
        )
        _debug(debug, f"OSProvisioningTimedOut details: {exc}")


def create_selray_vm(resource_group, subscription_id="", credential=None, location: str = LOCATION, debug: bool = False):
    if not subscription_id:
        _debug(debug, "Azure context missing in create_selray_vm; resolving credentials/subscription")
        credential, subscription_id = get_azure_context()
    cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)
    _debug(debug, f"Azure clients created for subscription '{subscription_id}'")

    effective_location = str(location or LOCATION).strip() or LOCATION
    _debug(debug, f"Using Azure location '{effective_location}'")
    ensure_rg(resource_client, resource_group, location=effective_location)
    _debug(debug, f"Resource group '{resource_group}' verified")
    owner = get_user()

    vm_name = sanitize_vm_name(f"selray-{owner}-{randint(1_000_000, 9_999_999)}")
    _debug(debug, f"Generated VM name '{vm_name}'")

    nic_id, nic_name, pip_id, _nsg_id, pip_name = create_networking(
        network_client, resource_group, location=effective_location, debug=debug
    )
    create_vm(
        resource_group, compute_client, nic_id, owner=owner, vm_name=vm_name, location=effective_location, debug=debug
    )

    # pip.ip_address will contain the actual IP address
    pip = network_client.public_ip_addresses.get(resource_group, pip_name)
    _debug(debug, f"VM provisioned; initial proxy IP resource '{pip_name}' resolved to '{pip.ip_address}'")

    proxy_ready_timeout = int(os.environ.get("AZURE_PROXY_READY_TIMEOUT", "420"))
    if not wait_for_proxy_ready(proxy_ip=pip.ip_address, timeout=proxy_ready_timeout, debug=debug):
        raise RuntimeError("Initial proxy health check failed")

    _debug(debug, f"Proxy health check passed for '{pip.ip_address}:3128'")
    return vm_name, f"http://{pip.ip_address}:3128", pip.ip_address, nic_name, credential, network_client, compute_client, owner
