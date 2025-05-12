import sys
import os
import argparse
import base64
import requests
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

RESOURCE_GROUP_NAME = "proxy-rg"
LOCATION = "eastus"  # Free-tier eligible region
USERNAME = "azureuser"
PASSWORD = "ChangeThisPassword123!"  # Should be more secure


def authenticate_azure():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscription = next(subscription_client.subscriptions.list())
        subscription_id = subscription.subscription_id

        print(f"✅ Authenticated to Azure. Subscription ID: {subscription_id}")
        return credential, subscription_id

    except Exception as e:
        print(f"❌ ERROR: Authentication or subscription lookup failed: {e}")
        sys.exit(1)


def get_my_ip():
    return requests.get("https://api.ipify.org").text


def create_resource_group(resource_client):
    resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {"location": LOCATION})


def create_network_resources(network_client, my_ip, index):
    vnet_name = f"proxy-vnet"
    subnet_name = f"proxy-subnet"
    ip_name = f"proxy-ip-{index}"
    nic_name = f"proxy-nic-{index}"
    nsg_name = f"proxy-nsg"

    network_client.virtual_networks.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        vnet_name,
        {
            "location": LOCATION,
            "address_space": {"address_prefixes": ["10.0.0.0/16"]}
        }
    ).result()

    subnet = network_client.subnets.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        vnet_name,
        subnet_name,
        {"address_prefix": "10.0.0.0/24"}
    ).result()

    ip_address = network_client.public_ip_addresses.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        ip_name,
        {
            "location": LOCATION,
            "public_ip_allocation_method": "Dynamic"
        }
    ).result()

    nsg = network_client.network_security_groups.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nsg_name,
        {"location": LOCATION}
    ).result()

    network_client.security_rules.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nsg_name,
        "AllowMyIP",
        {
            "access": "Allow",
            "direction": "Inbound",
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_range": "3128",
            "source_address_prefix": my_ip,
            "destination_address_prefix": "*",
            "priority": 100,
            "name": "AllowMyIP"
        }
    ).result()

    nic = network_client.network_interfaces.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nic_name,
        {
            "location": LOCATION,
            "ip_configurations": [{
                "name": "ipconfig1",
                "subnet": {"id": subnet.id},
                "public_ip_address": {"id": ip_address.id}
            }],
            "network_security_group": {"id": nsg.id}
        }
    ).result()

    return nic.id, ip_address.name


def create_vm(compute_client, nic_id, index):
    vm_name = f"proxy-vm-{index}"
    vm_parameters = {
        "location": LOCATION,
        "storage_profile": {
            "image_reference": {
                "publisher": "Canonical",
                "offer": "UbuntuServer",
                "sku": "18.04-LTS",
                "version": "latest"
            }
        },
        "hardware_profile": {
            "vm_size": "Standard_B1s"
        },
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": USERNAME,
            "admin_password": PASSWORD,
            "custom_data": generate_cloud_init_script()
        },
        "network_profile": {
            "network_interfaces": [{
                "id": nic_id,
                "primary": True
            }]
        }
    }

    compute_client.virtual_machines.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        vm_name,
        vm_parameters
    ).result()


def generate_cloud_init_script():
    my_ip = get_my_ip()
    cloud_init_script = f"""#cloud-config
package_update: true
packages:
  - tinyproxy
runcmd:
  - sed -i 's/^Port 8888/Port 3128/' /etc/tinyproxy/tinyproxy.conf
  - echo 'Allow {my_ip}/32' >> /etc/tinyproxy/tinyproxy.conf
  - echo 'ConnectPort 443' >> /etc/tinyproxy/tinyproxy.conf
  - echo 'ConnectPort 80' >> /etc/tinyproxy/tinyproxy.conf
  - systemctl restart tinyproxy
  - systemctl enable tinyproxy
"""
    cloud_init_base64 = base64.b64encode(cloud_init_script.encode("utf-8")).decode("utf-8")
    return cloud_init_base64


def register_provider_if_needed(resource_client, provider_namespace):
    provider = resource_client.providers.get(provider_namespace)
    if provider.registration_state.lower() != "registered":
        print(f"🔄 Registering provider '{provider_namespace}'...")
        resource_client.providers.register(provider_namespace)
        print(f"✅ Registered '{provider_namespace}' successfully.")


def delete_resource_group(resource_client):
    with tqdm(total=2, desc="Deleting Azure Proxies", dynamic_ncols=True, leave=True) as bar:
        try:
            delete_async_operation = resource_client.resource_groups.begin_delete(RESOURCE_GROUP_NAME)
            bar.update(1)
            bar.set_description("Waiting for deletion to complete. This may take a few minutes")
            delete_async_operation.wait()
            bar.set_description("✅ Azure VMs deleted")
            bar.update(1)
        except ResourceNotFoundError:
            bar.set_description("✅ No Azure VMs found")
            bar.update(2)


def delete_proxies():
    credential, subscription_id = authenticate_azure()
    resource_client = ResourceManagementClient(credential, subscription_id)
    delete_resource_group(resource_client)


def create_proxies(count):
    with tqdm(total=(3+(count*4)), desc="Creating Azure Proxies", dynamic_ncols=True) as bar:
        bar.set_description("Authenticating to Azure")
        credential, subscription_id = authenticate_azure()
        resource_client = ResourceManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        register_provider_if_needed(resource_client, "Microsoft.Network")
        register_provider_if_needed(resource_client, "Microsoft.Compute")
        register_provider_if_needed(resource_client, "Microsoft.Storage")

        bar.set_description("Getting your IP address from Azure")
        bar.update(1)
        my_ip = get_my_ip()
        bar.set_description("Creating Azure resource group")
        bar.update(1)
        create_resource_group(resource_client)

        proxies = []

        for i in range(count):
            bar.set_description(f"Creating VM NIC {i}")
            bar.update(1)
            nic_id, ip_name = create_network_resources(network_client, my_ip, i)
            bar.set_description(f"Creating VM {i}")
            bar.update(1)
            create_vm(compute_client, nic_id, i)
            bar.set_description(f"Getting VM {i} info")
            bar.update(1)
            ip_info = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, ip_name)
            proxy_url = f"http://{ip_info.ip_address}:3128"
            proxies.append({
                "type": "Azure",
                "ip_address": ip_info.ip_address,
                "url": proxy_url,
                "vm_index": i
            })
            #print(f"✅ Proxy {i + 1} URL: {proxy_url}")


    return proxies


def change_proxy_ip(vm_index):
    credential, subscription_id = authenticate_azure()

    network_client = NetworkManagementClient(credential, subscription_id)
    ip_name = f"proxy-ip-{vm_index}"
    nic_name = f"proxy-nic-{vm_index}"
    #print(f"🔁 Changing IP for {ip_name}...")

    # Get NIC and disassociate the current public IP
    nic = network_client.network_interfaces.get(RESOURCE_GROUP_NAME, nic_name)
    nic.ip_configurations[0].public_ip_address = None

    network_client.network_interfaces.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nic_name,
        {
            "location": LOCATION,
            "ip_configurations": [{
                "name": "ipconfig1",
                "subnet": nic.ip_configurations[0].subnet,
                "public_ip_address": None
            }],
            "network_security_group": {"id": nic.network_security_group.id}
        }
    ).result()

    # Now it's safe to delete the old IP
    network_client.public_ip_addresses.begin_delete(RESOURCE_GROUP_NAME, ip_name).wait()

    # Recreate the IP
    new_ip = network_client.public_ip_addresses.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        ip_name,
        {
            "location": LOCATION,
            "public_ip_allocation_method": "Dynamic"
        }
    ).result()

    # Re-associate new IP
    network_client.network_interfaces.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nic_name,
        {
            "location": LOCATION,
            "ip_configurations": [{
                "name": "ipconfig1",
                "subnet": nic.ip_configurations[0].subnet,
                "public_ip_address": {"id": new_ip.id}
            }],
            "network_security_group": {"id": nic.network_security_group.id}
        }
    ).result()

    # Refresh the IP info to get the assigned address
    refreshed_ip = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, ip_name)
    print(f"✅ New IP: {refreshed_ip.ip_address}")
    return refreshed_ip.ip_address


def list_proxies():
    credential, subscription_id = authenticate_azure()
    network_client = NetworkManagementClient(credential, subscription_id)

    console = Console()
    table = Table(title="Azure Proxy List")
    table.add_column("Proxy ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("Proxy URL", style="green")

    index = 0
    while True:
        ip_name = f"proxy-ip-{index}"
        try:
            ip = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, ip_name)
            if ip.ip_address:
                table.add_row(str(index), f"http://{ip.ip_address}:3128")
            index += 1
        except Exception:
            break

    if index == 0:
        console.print("⚠️ No proxies found.")
    else:
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Spin up Azure proxy VMs")
    parser.add_argument("--count", type=int, default=1, help="Number of proxies to create")
    parser.add_argument("--delete", action="store_true", help="Delete proxy resource group")
    parser.add_argument("--list", action="store_true", help="List proxies")
    args = parser.parse_args()

    if args.delete:
        delete_proxies()
    elif args.list:
        list_proxies()
    else:
        create_proxies(args.count)


if __name__ == "__main__":
    main()
