import sys
import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
import requests
import base64

RESOURCE_GROUP_NAME = "proxy-rg"
LOCATION = "eastus"  # Free-tier eligible region
VM_NAME = "proxy-vm"
USERNAME = "azureuser"
PASSWORD = "ChangeThisPassword123!"  # Should be more secure
NSG_NAME = "proxy-nsg"
IP_NAME = "proxy-ip"
NIC_NAME = "proxy-nic"
VNET_NAME = "proxy-vnet"
SUBNET_NAME = "proxy-subnet"

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

def create_network_resources(network_client, my_ip):
    network_client.virtual_networks.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    VNET_NAME,
    {
    "location": LOCATION,
    "address_space": {"address_prefixes": ["10.0.0.0/16"]}
    }
    ).result()

    subnet = network_client.subnets.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        VNET_NAME,
        SUBNET_NAME,
        {"address_prefix": "10.0.0.0/24"}
    ).result()

    ip_address = network_client.public_ip_addresses.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        IP_NAME,
        {
            "location": LOCATION,
            "public_ip_allocation_method": "Dynamic"
        }
    ).result()

    nsg = network_client.network_security_groups.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        NSG_NAME,
        {"location": LOCATION}
    ).result()

    network_client.security_rules.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        NSG_NAME,
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
        NIC_NAME,
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

    return nic.id, ip_address.id

def create_vm(compute_client, nic_id):
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
    "computer_name": VM_NAME,
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
        VM_NAME,
        vm_parameters
    ).result()

def generate_cloud_init_script():
    cloud_init_script = """#cloud-config
package_update: true
packages:
  - tinyproxy
runcmd:
  - sed -i 's/^Allow 127\\.0\\.0\\.1$/Allow 0.0.0.0\\/0/' /etc/tinyproxy/tinyproxy.conf
  - sed -i 's/^#Allow /Allow /' /etc/tinyproxy/tinyproxy.conf
  - sed -i 's/^Port 8888/Port 3128/' /etc/tinyproxy/tinyproxy.conf
  - systemctl restart tinyproxy
  - systemctl enable tinyproxy
"""
    # Encode cloud-init script to Base64
    cloud_init_base64 = base64.b64encode(cloud_init_script.encode("utf-8")).decode("utf-8")
    return cloud_init_base64


def register_provider_if_needed(resource_client, provider_namespace):
    provider = resource_client.providers.get(provider_namespace)
    if provider.registration_state.lower() != "registered":
        print(f"🔄 Registering provider '{provider_namespace}'...")
        resource_client.providers.register(provider_namespace)
        print(f"✅ Registered '{provider_namespace}' successfully.")


def delete_resource_group(resource_client):
    print(f"🗑️ Deleting resource group '{RESOURCE_GROUP_NAME}'...")
    delete_async_operation = resource_client.resource_groups.begin_delete(RESOURCE_GROUP_NAME)
    delete_async_operation.wait()
    print(f"✅ Resource group '{RESOURCE_GROUP_NAME}' deleted.")


def delete_proxy():
    credential, subscription_id = authenticate_azure()
    resource_client = ResourceManagementClient(credential, subscription_id)
    delete_resource_group(resource_client)


def create_proxy():
    credential, subscription_id = authenticate_azure()

    resource_client = ResourceManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)

    register_provider_if_needed(resource_client, "Microsoft.Network")
    register_provider_if_needed(resource_client, "Microsoft.Compute")
    register_provider_if_needed(resource_client, "Microsoft.Storage")

    my_ip = get_my_ip()
    create_resource_group(resource_client)
    nic_id, ip_id = create_network_resources(network_client, my_ip)
    create_vm(compute_client, nic_id)

    ip_info = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, IP_NAME)
    proxy_url = f"http://{ip_info.ip_address}:3128"

    print(f"✅ Proxy URL: {proxy_url}")

if __name__ == "__main__":
    main()
