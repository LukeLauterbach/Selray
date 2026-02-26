from .AzureAuth import get_azure_context, make_azure_clients
from .CheckProxy import wait_for_proxy_ready
from .GetMyInfo import get_public_ip, get_user
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
import os
from random import randint
from string import ascii_lowercase,digits
from secrets import choice
import re

LOCATION = os.environ.get("AZURE_LOCATION", "eastus")


def ensure_rg(resource_client: ResourceManagementClient, resource_group_name) -> None:
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
            resource_group_name, {"location": LOCATION}
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
        # RG exists but we couldn't create/update it; continue with a clear warning.
        print(
            f"[!] Could not create/update resource group '{resource_group_name}' "
            f"(likely due to permissions). Using existing RG."
        )


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


def create_networking(network_client: NetworkManagementClient, resource_group):
    suffix = rand_suffix()

    vnet_name = f"vnet-proxy-{suffix}"
    subnet_name = "subnet-proxy"
    nsg_name = f"nsg-proxy-{suffix}"
    pip_name = f"pip-proxy-{suffix}"
    nic_name = f"nic-proxy-{suffix}"

    network_client.virtual_networks.begin_create_or_update(
        resource_group,
        vnet_name,
        {
            "location": LOCATION,
            "address_space": {"address_prefixes": ["10.10.0.0/16"]},
            "subnets": [{"name": subnet_name, "address_prefix": "10.10.1.0/24"}],
        },
    ).result()

    subnet = network_client.subnets.get(resource_group, vnet_name, subnet_name)

    nsg = network_client.network_security_groups.begin_create_or_update(
        resource_group,
        nsg_name,
        {"location": LOCATION},
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

    pip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group,
        pip_name,
        {
            "location": LOCATION,
            "public_ip_allocation_method": "Static",
            "sku": {"name": "Standard"},
        },
    ).result()

    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group,
        nic_name,
        {
            "location": LOCATION,
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


def create_vm(resource_group, compute_client: ComputeManagementClient, nic_id: str, owner="defaultUser", vm_name="") -> None:
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
        "location": LOCATION,

        # 👇 Tags live here (top-level)
        "tags": {
            "owner": owner,
            "purpose": "selray",
            "project": "proxy-rotation",
        },

        "hardware_profile": {"vm_size": os.environ.get("AZURE_VM_SIZE", "Standard_B1s")},
        "storage_profile": {"image_reference": image_ref},
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": admin_username,
            "linux_configuration": {
                "disable_password_authentication": True,
                "ssh": {
                    "public_keys": [
                        {
                            "path": f"/home/{admin_username}/.ssh/authorized_keys",
                            "key_data": admin_ssh_public_key,
                        }
                    ]
                },
            },
        },
        "network_profile": {
            "network_interfaces": [
                {"id": nic_id, "primary": True}
            ]
        },
        "user_data": user_data,
    }

    compute_client.virtual_machines.begin_create_or_update(
        resource_group, vm_name, vm_params
    ).result()


def create_selray_vm(resource_group, subscription_id="", credential=None):
    if not subscription_id:
        credential, subscription_id = get_azure_context()
    cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    ensure_rg(resource_client, resource_group)
    owner = get_user()

    vm_name = sanitize_vm_name(f"selray-{owner}-{randint(1_000_000, 9_999_999)}")

    nic_id, nic_name, pip_id, _nsg_id, pip_name = create_networking(network_client, resource_group)
    create_vm(resource_group, compute_client, nic_id, owner=owner, vm_name=vm_name)

    # pip.ip_address will contain the actual IP address
    pip = network_client.public_ip_addresses.get(resource_group, pip_name)
    #print(f"[+] Initial proxy IP: {pip.ip_address}")

    if not wait_for_proxy_ready(proxy_ip=pip.ip_address):
        raise RuntimeError("Initial proxy health check failed")

    return vm_name, f"http://{pip.ip_address}:3128", pip.ip_address, nic_name, credential, network_client, compute_client, owner
