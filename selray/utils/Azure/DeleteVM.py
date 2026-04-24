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
    vnet_names: List[str]
    disk_names: List[str]  # includes OS disk (and optionally data disks)


def _delete_resources_parallel(
    *,
    names: List[str],
    kind: str,
    begin_delete_fn,
    status_cb: Optional[Callable[[str], None]] = None,
    max_workers: int = 8,
) -> None:
    """
    Delete same-kind Azure resources in parallel and raise one aggregated error if needed.
    """
    if not names:
        return

    errors: List[str] = []
    worker_count = max(1, min(max_workers, len(names)))

    def _delete_one(resource_name: str) -> Optional[str]:
        try:
            if status_cb:
                status_cb(f"Deleting {kind}: {resource_name}")
            begin_delete_fn(resource_name).result()
            return None
        except ResourceNotFoundError:
            if status_cb:
                status_cb(f"{kind} already deleted: {resource_name}")
            return None
        except HttpResponseError as e:
            return f"{resource_name}: {e}"

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(_delete_one, n) for n in names]
        for fut in as_completed(futures):
            err = fut.result()
            if err:
                errors.append(err)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(f"Failed to delete {len(errors)} {kind}(s). First errors: {preview}")


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
    virtual network(s) referenced by NIC subnet(s),
    and managed disk(s) attached to the VM (OS disk + optionally data disks).
    """
    vm = compute_client.virtual_machines.get(resource_group, vm_name)

    nic_names: List[str] = []
    pip_names: List[str] = []
    nsg_names: List[str] = []
    vnet_names: List[str] = []
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

            # Subnet ID looks like:
            # .../virtualNetworks/{vnet}/subnets/{subnet}
            subnet_obj = getattr(ipcfg, "subnet", None)
            subnet_id = getattr(subnet_obj, "id", None) if subnet_obj is not None else None
            if subnet_id:
                parts = subnet_id.split("/")
                for i, part in enumerate(parts):
                    if part.lower() == "virtualnetworks" and i + 1 < len(parts):
                        vnet_names.append(parts[i + 1])
                        break

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
        vnet_names=_dedup(vnet_names),
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
    delete_vnets: bool = True,
    delete_disks: bool = True,
    include_data_disks: bool = True,
    discover_attached: bool = True,
    status_cb: Optional[Callable[[str], None]] = None,
) -> None:
    """
    Deletes a VM by name. If clients aren't provided, it creates them.
    Optionally discovers and deletes attached NIC(s), Public IP(s), NIC NSG(s),
    virtual network(s), and managed disks (OS + data).
    """

    if not subscription_id or not network_client or not compute_client:
        credential, subscription_id = get_azure_context()
        credential, resource_client, network_client, compute_client = make_azure_clients(subscription_id)

    attached = VmAttachedResources(
        nic_names=[],
        public_ip_names=[],
        nsg_names=[],
        vnet_names=[],
        disk_names=[],
    )

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
            attached = VmAttachedResources(
                nic_names=[],
                public_ip_names=[],
                nsg_names=[],
                vnet_names=[],
                disk_names=[],
            )
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

    # 2) Phase A: delete NICs and disks in parallel (independent once VM is deleted)
    phase_a_errors: List[str] = []
    phase_a_workers = []
    with ThreadPoolExecutor(max_workers=2) as phase_a_executor:
        if delete_nics and attached.nic_names:
            phase_a_workers.append(
                phase_a_executor.submit(
                    _delete_resources_parallel,
                    names=attached.nic_names,
                    kind="NIC",
                    begin_delete_fn=lambda n: network_client.network_interfaces.begin_delete(resource_group, n),
                    status_cb=status_cb,
                )
            )
        if delete_disks and attached.disk_names:
            phase_a_workers.append(
                phase_a_executor.submit(
                    _delete_resources_parallel,
                    names=attached.disk_names,
                    kind="Disk",
                    begin_delete_fn=lambda n: compute_client.disks.begin_delete(resource_group, n),
                    status_cb=status_cb,
                )
            )
        for future in as_completed(phase_a_workers):
            try:
                future.result()
            except Exception as e:
                phase_a_errors.append(str(e))

    if phase_a_errors:
        raise RuntimeError("; ".join(phase_a_errors))

    # 3) Phase B: delete PIPs and NSGs in parallel (after NIC detach/deletion)
    phase_b_errors: List[str] = []
    phase_b_workers = []
    with ThreadPoolExecutor(max_workers=2) as phase_b_executor:
        if delete_public_ips and attached.public_ip_names:
            phase_b_workers.append(
                phase_b_executor.submit(
                    _delete_resources_parallel,
                    names=attached.public_ip_names,
                    kind="Public IP",
                    begin_delete_fn=lambda n: network_client.public_ip_addresses.begin_delete(resource_group, n),
                    status_cb=status_cb,
                )
            )
        if delete_nsgs and attached.nsg_names:
            phase_b_workers.append(
                phase_b_executor.submit(
                    _delete_resources_parallel,
                    names=attached.nsg_names,
                    kind="NSG",
                    begin_delete_fn=lambda n: network_client.network_security_groups.begin_delete(resource_group, n),
                    status_cb=status_cb,
                )
            )
        for future in as_completed(phase_b_workers):
            try:
                future.result()
            except Exception as e:
                phase_b_errors.append(str(e))

    if phase_b_errors:
        raise RuntimeError("; ".join(phase_b_errors))

    # 4) Phase C: delete VNets last (depends on subnet/NIC lifecycle completion)
    if delete_vnets and attached.vnet_names:
        _delete_resources_parallel(
            names=attached.vnet_names,
            kind="VNet",
            begin_delete_fn=lambda n: network_client.virtual_networks.begin_delete(resource_group, n),
            status_cb=status_cb,
        )


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
      - attached Virtual Network(s)
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
