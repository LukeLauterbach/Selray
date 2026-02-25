from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Callable
from azure.identity import DefaultAzureCredential
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from .AzureAuth import get_azure_context, make_azure_clients
from .GetMyInfo import get_user


@dataclass
class VmAttachedResources:
    nic_names: List[str]
    public_ip_names: List[str]
    nsg_names: List[str]
    disk_names: List[str]  # includes OS disk (and optionally data disks)


def _parse_name_from_resource_id(resource_id: str) -> str:
    return resource_id.split("/")[-1]


def _dedup(seq: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def discover_vm_attached_resources(
    compute_client: ComputeManagementClient,
    network_client: NetworkManagementClient,
    resource_group: str,
    vm_name: str,
    *,
    include_data_disks: bool = True,
) -> VmAttachedResources:
    """
    Discovers NIC(s), Public IP(s) attached to those NIC(s),
    network security group(s) attached to those NIC(s),
    and managed disk(s) attached to the VM (OS disk + optionally data disks).
    """
    vm = compute_client.virtual_machines.get(resource_group, vm_name)

    nic_names: List[str] = []
    pip_names: List[str] = []
    nsg_names: List[str] = []
    disk_names: List[str] = []

    # NICs + PIPs
    for nic_ref in (vm.network_profile.network_interfaces or []):
        nic_id = getattr(nic_ref, "id", None)
        if not nic_id:
            continue

        nic_name = _parse_name_from_resource_id(nic_id)
        nic_names.append(nic_name)

        nic = network_client.network_interfaces.get(resource_group, nic_name)
        nsg_obj = getattr(nic, "network_security_group", None)
        nsg_id = getattr(nsg_obj, "id", None) if nsg_obj is not None else None
        if nsg_id:
            nsg_names.append(_parse_name_from_resource_id(nsg_id))

        for ipcfg in (nic.ip_configurations or []):
            pip_obj = getattr(ipcfg, "public_ip_address", None)
            pip_id = getattr(pip_obj, "id", None) if pip_obj is not None else None
            if pip_id:
                pip_names.append(_parse_name_from_resource_id(pip_id))

    # OS disk
    os_disk = getattr(vm.storage_profile, "os_disk", None)
    if os_disk:
        managed = getattr(os_disk, "managed_disk", None)
        disk_id = getattr(managed, "id", None) if managed else None
        if disk_id:
            disk_names.append(_parse_name_from_resource_id(disk_id))

    # Data disks (optional)
    if include_data_disks:
        for dd in (vm.storage_profile.data_disks or []):
            managed = getattr(dd, "managed_disk", None)
            disk_id = getattr(managed, "id", None) if managed else None
            if disk_id:
                disk_names.append(_parse_name_from_resource_id(disk_id))

    return VmAttachedResources(
        nic_names=_dedup(nic_names),
        public_ip_names=_dedup(pip_names),
        nsg_names=_dedup(nsg_names),
        disk_names=_dedup(disk_names),
    )


def delete_vm_by_name(
    resource_group,
    vm_name,
    *,
    credential=None,
    subscription_id=None,
    compute_client: Optional[ComputeManagementClient] = None,
    network_client: Optional[NetworkManagementClient] = None,
    delete_nics: bool = True,
    delete_public_ips: bool = True,
    delete_nsgs: bool = True,
    delete_disks: bool = True,
    include_data_disks: bool = True,
    discover_attached: bool = True,
    status_cb: Optional[Callable[[str], None]] = None,
) -> None:
    """
    Deletes a VM by name. If clients aren't provided, it creates them.
    Optionally discovers and deletes attached NIC(s), Public IP(s), NIC NSG(s),
    and managed disks (OS + data).
    """

    if not subscription_id or not network_client or not compute_client:
        credential, subscription_id = get_azure_context()
        credential, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    attached = VmAttachedResources(nic_names=[], public_ip_names=[], nsg_names=[], disk_names=[])

    # Discover resources BEFORE deleting the VM (after deletion you can’t reliably read references)
    if discover_attached:
        try:
            attached = discover_vm_attached_resources(
                compute_client,
                network_client,
                resource_group,
                vm_name,
                include_data_disks=include_data_disks,
            )
        except ResourceNotFoundError:
            if status_cb:
                status_cb(f"Skipping missing VM: {vm_name}")
            attached = VmAttachedResources(nic_names=[], public_ip_names=[], nsg_names=[], disk_names=[])
        except HttpResponseError as e:
            raise RuntimeError(f"Failed discovering resources for VM '{vm_name}': {e}") from e

    # 1) Delete VM first
    try:
        if status_cb:
            status_cb(f"Deleting VM: {vm_name}")
        compute_client.virtual_machines.begin_delete(resource_group, vm_name).result()
    except ResourceNotFoundError:
        if status_cb:
            status_cb(f"VM already deleted: {vm_name}")
    except HttpResponseError as e:
        raise RuntimeError(f"Failed to delete VM '{vm_name}': {e}") from e

    # 2) Delete NICs
    if delete_nics:
        for nic_name in attached.nic_names:
            try:
                if status_cb:
                    status_cb(f"Deleting NIC: {nic_name}")
                network_client.network_interfaces.begin_delete(resource_group, nic_name).result()
            except ResourceNotFoundError:
                if status_cb:
                    status_cb(f"NIC already deleted: {nic_name}")
            except HttpResponseError as e:
                raise RuntimeError(f"Failed to delete NIC '{nic_name}': {e}") from e

    # 3) Delete Public IPs
    if delete_public_ips:
        for pip_name in attached.public_ip_names:
            try:
                if status_cb:
                    status_cb(f"Deleting Public IP: {pip_name}")
                network_client.public_ip_addresses.begin_delete(resource_group, pip_name).result()
            except ResourceNotFoundError:
                if status_cb:
                    status_cb(f"Public IP already deleted: {pip_name}")
            except HttpResponseError as e:
                raise RuntimeError(f"Failed to delete Public IP '{pip_name}': {e}") from e

    # 4) Delete NIC-attached NSGs
    if delete_nsgs:
        for nsg_name in attached.nsg_names:
            try:
                if status_cb:
                    status_cb(f"Deleting NSG: {nsg_name}")
                network_client.network_security_groups.begin_delete(resource_group, nsg_name).result()
            except ResourceNotFoundError:
                if status_cb:
                    status_cb(f"NSG already deleted: {nsg_name}")
            except HttpResponseError as e:
                raise RuntimeError(f"Failed to delete NSG '{nsg_name}': {e}") from e

    # 5) Delete managed disks (OS disk + data disks)
    if delete_disks:
        for disk_name in attached.disk_names:
            try:
                if status_cb:
                    status_cb(f"Deleting Disk: {disk_name}")
                compute_client.disks.begin_delete(resource_group, disk_name).result()
            except ResourceNotFoundError:
                if status_cb:
                    status_cb(f"Disk already deleted: {disk_name}")
            except HttpResponseError as e:
                raise RuntimeError(f"Failed to delete disk '{disk_name}': {e}") from e


def _resource_group_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Could not parse resource group from id: {resource_id}")


def delete_vms_by_tags(
    *,
    subscription_id: str,
    required_tags: Dict[str, str],
    credential=None,
    compute_client=None,
    network_client=None,
    include_data_disks: bool = True,
    max_workers: int = 10,
) -> List[str]:
    """
    Deletes all VMs that have ALL key/value pairs in `required_tags`.

    Also deletes:
      - attached NIC(s)
      - attached Public IP(s)
      - NIC-attached NSG(s)
      - OS disk + (optionally) data disks

    Returns: list of VM resource IDs matched (deleted)

    Requires you to have `delete_vm_by_name(...)` available (the version that deletes NIC/PIP/NSG/disks).
    """

    # Use your helper if you already have one; otherwise, keep it simple here:
    if compute_client is None or network_client is None:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient

        if credential is None:
            credential = DefaultAzureCredential()

        if compute_client is None:
            compute_client = ComputeManagementClient(credential, subscription_id)
        if network_client is None:
            network_client = NetworkManagementClient(credential, subscription_id)

    matched: List[Tuple[str, str, str]] = []

    # First pass: collect matching VMs so we can show accurate progress.
    for vm in compute_client.virtual_machines.list_all():
        vm_tags = getattr(vm, "tags", None) or {}
        vm_name = getattr(vm, "name", None)
        vm_id = getattr(vm, "id", None)

        if not vm_name or not vm_id:
            continue

        # Must contain ALL required tags with exact values
        if any(vm_tags.get(k) != v for k, v in required_tags.items()):
            continue

        rg = _resource_group_from_id(vm_id)
        matched.append((vm_id, vm_name, rg))

    if not matched:
        return []

    matched_vm_ids = [vm_id for vm_id, _, _ in matched]
    worker_count = max(1, min(max_workers, len(matched)))
    deleted_vm_ids: List[str] = []
    errors: List[str] = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Deleting", total=len(matched))
        if worker_count == 1:
            for vm_id, vm_name, rg in matched:
                progress.update(task_id, description=f"Deleting: {vm_name}")
                try:
                    delete_vm_by_name(
                        subscription_id=subscription_id,
                        resource_group=rg,
                        vm_name=vm_name,
                        credential=credential,
                        compute_client=compute_client,
                        network_client=network_client,
                        delete_disks=True,             # OS disk + data disks
                        include_data_disks=include_data_disks,
                    )
                    deleted_vm_ids.append(vm_id)
                except Exception as e:
                    errors.append(f"{vm_name}: {e}")
                finally:
                    progress.advance(task_id, 1)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_vm = {
                    executor.submit(
                        delete_vm_by_name,
                        subscription_id=subscription_id,
                        resource_group=rg,
                        vm_name=vm_name,
                        credential=credential,
                        compute_client=compute_client,
                        network_client=network_client,
                        delete_disks=True,             # OS disk + data disks
                        include_data_disks=include_data_disks,
                    ): (vm_id, vm_name)
                    for vm_id, vm_name, rg in matched
                }

                for future in as_completed(future_to_vm):
                    vm_id, vm_name = future_to_vm[future]
                    try:
                        future.result()
                        deleted_vm_ids.append(vm_id)
                        progress.update(task_id, description=f"Deleted: {vm_name}")
                    except Exception as e:
                        errors.append(f"{vm_name}: {e}")
                        progress.update(task_id, description=f"Failed: {vm_name}")
                    finally:
                        progress.advance(task_id, 1)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(
            f"Failed to delete {len(errors)} of {len(matched_vm_ids)} VM(s). First errors: {preview}"
        )

    return deleted_vm_ids

def delete_selray_vms(*, nuke: bool = False, max_workers: int = 6) -> List[str]:
    credential, subscription_id = get_azure_context()
    required_tags = {"purpose": "selray"}
    if not nuke:
        owner = get_user()
        required_tags["owner"] = owner

    deleted = delete_vms_by_tags(
        subscription_id=subscription_id,
        credential=credential,
        required_tags=required_tags,
        max_workers=max_workers,
    )
    return deleted
