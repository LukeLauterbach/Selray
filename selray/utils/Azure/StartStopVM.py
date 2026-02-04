from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from .AzureAuth import get_azure_context, make_azure_clients
from .CheckProxy import wait_for_proxy_ready

def get_vm_public_ip(
    compute_client: ComputeManagementClient,
    network_client: NetworkManagementClient,
    resource_group: str,
    vm_name: str,
):
    if not compute_client or not network_client:
        credential, subscription_id = get_azure_context()
        cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    vm = compute_client.virtual_machines.get(resource_group, vm_name)

    nic_id = vm.network_profile.network_interfaces[0].id
    nic_name = nic_id.split("/")[-1]

    nic = network_client.network_interfaces.get(resource_group, nic_name)

    ip_config = nic.ip_configurations[0]
    if not ip_config.public_ip_address:
        return None

    pip_id = ip_config.public_ip_address.id
    pip_name = pip_id.split("/")[-1]

    public_ip = network_client.public_ip_addresses.get(
        resource_group,
        pip_name,
    )

    return public_ip.ip_address


def start_vm(vm_name, compute_client=None, network_client=None, resource_group=""):
    if not compute_client or not network_client:
        credential, subscription_id = get_azure_context()
        cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    poller = compute_client.virtual_machines.begin_start(
        resource_group_name=resource_group,
        vm_name=vm_name,
    )
    poller.result()
    proxy_ip = get_vm_public_ip(vm_name=vm_name,
                                network_client=network_client,
                                compute_client=compute_client,
                                resource_group=resource_group)
    wait_for_proxy_ready(proxy_ip=proxy_ip)

    return proxy_ip

def stop_vm(vm_name, compute_client=None, resource_group=""):
    if not compute_client:
        credential, subscription_id = get_azure_context()
        cred, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    poller = compute_client.virtual_machines.begin_deallocate(
        resource_group_name=resource_group,
        vm_name=vm_name,
    )
    poller.result()
