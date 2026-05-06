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


def _resource_name_from_id(resource_id: str, resource_type: str) -> str:
    parts = resource_id.split("/")
    resource_type = resource_type.lower()
    for i, p in enumerate(parts):
        if p.lower() == resource_type and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Could not parse {resource_type} name from id: {resource_id}")


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


def delete_unattached_disks_by_tags(
    *,
    subscription_id: str,
    required_tags: Dict[str, str],
    credential=None,
    compute_client=None,
    max_workers: int = 10,
) -> List[str]:
    """
    Deletes managed disks that match all required tags and are not attached to any VM.

    Azure keeps attached disks protected through the disk's `managed_by` fields.
    Skipping those fields means stopped/deallocated VMs keep their disks too.
    """
    if compute_client is None:
        if credential is None:
            credential = DefaultAzureCredential()
        compute_client = ComputeManagementClient(credential, subscription_id)

    matched: List[Tuple[str, str, str]] = []

    for disk in compute_client.disks.list():
        disk_tags = getattr(disk, "tags", None) or {}
        disk_name = getattr(disk, "name", None)
        disk_id = getattr(disk, "id", None)

        if not disk_name or not disk_id:
            continue

        if any(disk_tags.get(k) != v for k, v in required_tags.items()):
            continue

        managed_by = getattr(disk, "managed_by", None)
        managed_by_extended = getattr(disk, "managed_by_extended", None) or []
        if managed_by or managed_by_extended:
            continue

        rg = _resource_group_from_id(disk_id)
        matched.append((disk_id, disk_name, rg))

    if not matched:
        return []

    worker_count = max(1, min(max_workers, len(matched)))
    errors: List[str] = []

    def _delete_one(disk_id: str, disk_name: str, rg: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            compute_client.disks.begin_delete(rg, disk_name).result()
            return disk_id, None
        except ResourceNotFoundError:
            return disk_id, None
        except HttpResponseError as e:
            return None, f"{disk_name}: {e}"

    deleted_disk_ids: List[str] = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Deleting orphaned disks", total=len(matched))
        if worker_count == 1:
            for disk_id, disk_name, rg in matched:
                progress.update(task_id, description=f"Deleting disk: {disk_name}")
                deleted_id, err = _delete_one(disk_id, disk_name, rg)
                if deleted_id:
                    deleted_disk_ids.append(deleted_id)
                if err:
                    errors.append(err)
                progress.advance(task_id, 1)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_disk = {
                    executor.submit(_delete_one, disk_id, disk_name, rg): disk_name
                    for disk_id, disk_name, rg in matched
                }

                for future in as_completed(future_to_disk):
                    disk_name = future_to_disk[future]
                    try:
                        deleted_id, err = future.result()
                        if deleted_id:
                            deleted_disk_ids.append(deleted_id)
                        if err:
                            errors.append(err)
                            progress.update(task_id, description=f"Failed disk: {disk_name}")
                        else:
                            progress.update(task_id, description=f"Deleted disk: {disk_name}")
                    except Exception as e:
                        errors.append(f"{disk_name}: {e}")
                        progress.update(task_id, description=f"Failed disk: {disk_name}")
                    finally:
                        progress.advance(task_id, 1)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(
            f"Failed to delete {len(errors)} of {len(matched)} disk(s). First errors: {preview}"
        )

    return deleted_disk_ids


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


def delete_unattached_selray_disks(*, max_workers: int = 10) -> List[str]:
    credential, subscription_id = get_azure_context()
    return delete_unattached_disks_by_tags(
        subscription_id=subscription_id,
        credential=credential,
        required_tags={"purpose": "selray"},
        max_workers=max_workers,
    )


def _vm_is_running(compute_client, resource_group: str, vm_name: str) -> bool:
    instance_view = compute_client.virtual_machines.instance_view(resource_group, vm_name)
    for status in getattr(instance_view, "statuses", None) or []:
        if getattr(status, "code", None) == "PowerState/running":
            return True
    return False


def _running_vm_vnet_keys(compute_client, network_client) -> set[Tuple[str, str]]:
    protected_vnets: set[Tuple[str, str]] = set()

    for vm in compute_client.virtual_machines.list_all():
        vm_name = getattr(vm, "name", None)
        vm_id = getattr(vm, "id", None)
        if not vm_name or not vm_id:
            continue

        vm_rg = _resource_group_from_id(vm_id)
        try:
            should_protect = _vm_is_running(compute_client, vm_rg, vm_name)
        except ResourceNotFoundError:
            continue
        except HttpResponseError:
            should_protect = True

        if not should_protect:
            continue

        network_profile = getattr(vm, "network_profile", None)
        for nic_ref in getattr(network_profile, "network_interfaces", None) or []:
            nic_id = getattr(nic_ref, "id", None)
            if not nic_id:
                continue

            try:
                nic_rg = _resource_group_from_id(nic_id)
                nic_name = _resource_name_from_id(nic_id, "networkInterfaces")
                nic = network_client.network_interfaces.get(nic_rg, nic_name)
            except (ValueError, ResourceNotFoundError, HttpResponseError):
                continue

            for ipcfg in getattr(nic, "ip_configurations", None) or []:
                subnet_obj = getattr(ipcfg, "subnet", None)
                subnet_id = getattr(subnet_obj, "id", None) if subnet_obj is not None else None
                if not subnet_id:
                    continue
                try:
                    vnet_rg = _resource_group_from_id(subnet_id)
                    vnet_name = _resource_name_from_id(subnet_id, "virtualNetworks")
                except ValueError:
                    continue
                protected_vnets.add((vnet_rg.lower(), vnet_name.lower()))

    return protected_vnets


def _running_vm_public_ip_keys(compute_client, network_client) -> set[Tuple[str, str]]:
    protected_public_ips: set[Tuple[str, str]] = set()

    for vm in compute_client.virtual_machines.list_all():
        vm_name = getattr(vm, "name", None)
        vm_id = getattr(vm, "id", None)
        if not vm_name or not vm_id:
            continue

        vm_rg = _resource_group_from_id(vm_id)
        try:
            should_protect = _vm_is_running(compute_client, vm_rg, vm_name)
        except ResourceNotFoundError:
            continue
        except HttpResponseError:
            should_protect = True

        if not should_protect:
            continue

        network_profile = getattr(vm, "network_profile", None)
        for nic_ref in getattr(network_profile, "network_interfaces", None) or []:
            nic_id = getattr(nic_ref, "id", None)
            if not nic_id:
                continue

            try:
                nic_rg = _resource_group_from_id(nic_id)
                nic_name = _resource_name_from_id(nic_id, "networkInterfaces")
                nic = network_client.network_interfaces.get(nic_rg, nic_name)
            except (ValueError, ResourceNotFoundError, HttpResponseError):
                continue

            for ipcfg in getattr(nic, "ip_configurations", None) or []:
                pip_obj = getattr(ipcfg, "public_ip_address", None)
                pip_id = getattr(pip_obj, "id", None) if pip_obj is not None else None
                if not pip_id:
                    continue
                try:
                    pip_rg = _resource_group_from_id(pip_id)
                    pip_name = _resource_name_from_id(pip_id, "publicIPAddresses")
                except ValueError:
                    continue
                protected_public_ips.add((pip_rg.lower(), pip_name.lower()))

    return protected_public_ips


def _running_vm_nsg_keys(compute_client, network_client) -> set[Tuple[str, str]]:
    protected_nsgs: set[Tuple[str, str]] = set()

    for vm in compute_client.virtual_machines.list_all():
        vm_name = getattr(vm, "name", None)
        vm_id = getattr(vm, "id", None)
        if not vm_name or not vm_id:
            continue

        vm_rg = _resource_group_from_id(vm_id)
        try:
            should_protect = _vm_is_running(compute_client, vm_rg, vm_name)
        except ResourceNotFoundError:
            continue
        except HttpResponseError:
            should_protect = True

        if not should_protect:
            continue

        network_profile = getattr(vm, "network_profile", None)
        for nic_ref in getattr(network_profile, "network_interfaces", None) or []:
            nic_id = getattr(nic_ref, "id", None)
            if not nic_id:
                continue

            try:
                nic_rg = _resource_group_from_id(nic_id)
                nic_name = _resource_name_from_id(nic_id, "networkInterfaces")
                nic = network_client.network_interfaces.get(nic_rg, nic_name)
            except (ValueError, ResourceNotFoundError, HttpResponseError):
                continue

            nsg_obj = getattr(nic, "network_security_group", None)
            nsg_id = getattr(nsg_obj, "id", None) if nsg_obj is not None else None
            if not nsg_id:
                continue
            try:
                nsg_rg = _resource_group_from_id(nsg_id)
                nsg_name = _resource_name_from_id(nsg_id, "networkSecurityGroups")
            except ValueError:
                continue
            protected_nsgs.add((nsg_rg.lower(), nsg_name.lower()))

    return protected_nsgs


def _public_ip_nic_ref(public_ip) -> Optional[Tuple[str, str]]:
    ip_configuration = getattr(public_ip, "ip_configuration", None)
    ip_configuration_id = getattr(ip_configuration, "id", None) if ip_configuration is not None else None
    if not ip_configuration_id:
        return None

    try:
        return (
            _resource_group_from_id(ip_configuration_id),
            _resource_name_from_id(ip_configuration_id, "networkInterfaces"),
        )
    except ValueError:
        return None


def _remove_public_ip_from_nic(network_client, resource_group: str, nic_name: str, public_ip_id: str) -> None:
    nic = network_client.network_interfaces.get(resource_group, nic_name)
    changed = False
    for ipcfg in getattr(nic, "ip_configurations", None) or []:
        pip_obj = getattr(ipcfg, "public_ip_address", None)
        pip_id = getattr(pip_obj, "id", None) if pip_obj is not None else None
        if pip_id and pip_id.lower() == public_ip_id.lower():
            ipcfg.public_ip_address = None
            changed = True

    if changed:
        network_client.network_interfaces.begin_create_or_update(resource_group, nic_name, nic).result()


def _detach_nsg_from_proxy_nics(network_client, resource_group: str, nsg_id: str) -> None:
    for nic in network_client.network_interfaces.list(resource_group):
        nic_name = getattr(nic, "name", None)
        if not nic_name or not nic_name.lower().startswith("nic-proxy-"):
            continue

        nsg_obj = getattr(nic, "network_security_group", None)
        attached_nsg_id = getattr(nsg_obj, "id", None) if nsg_obj is not None else None
        if not attached_nsg_id or attached_nsg_id.lower() != nsg_id.lower():
            continue

        nic.network_security_group = None
        network_client.network_interfaces.begin_create_or_update(resource_group, nic_name, nic).result()


def _nic_uses_vnet(nic, resource_group: str, vnet_name: str) -> bool:
    for ipcfg in getattr(nic, "ip_configurations", None) or []:
        subnet_obj = getattr(ipcfg, "subnet", None)
        subnet_id = getattr(subnet_obj, "id", None) if subnet_obj is not None else None
        if not subnet_id:
            continue
        try:
            subnet_rg = _resource_group_from_id(subnet_id)
            subnet_vnet = _resource_name_from_id(subnet_id, "virtualNetworks")
        except ValueError:
            continue
        if subnet_rg.lower() == resource_group.lower() and subnet_vnet.lower() == vnet_name.lower():
            return True
    return False


def _discover_proxy_nic_dependencies_for_vnet(network_client, resource_group: str, vnet_name: str) -> VmAttachedResources:
    nic_names: List[str] = []
    pip_names: List[str] = []
    nsg_names: List[str] = []

    for nic in network_client.network_interfaces.list(resource_group):
        nic_name = getattr(nic, "name", None)
        if not nic_name or not nic_name.lower().startswith("nic-proxy-"):
            continue
        if not _nic_uses_vnet(nic, resource_group, vnet_name):
            continue

        nic_names.append(nic_name)

        nsg_obj = getattr(nic, "network_security_group", None)
        nsg_id = getattr(nsg_obj, "id", None) if nsg_obj is not None else None
        if nsg_id:
            nsg_names.append(_parse_name_from_resource_id(nsg_id))

        for ipcfg in getattr(nic, "ip_configurations", None) or []:
            pip_obj = getattr(ipcfg, "public_ip_address", None)
            pip_id = getattr(pip_obj, "id", None) if pip_obj is not None else None
            if pip_id:
                pip_names.append(_parse_name_from_resource_id(pip_id))

    return VmAttachedResources(
        nic_names=_dedup(nic_names),
        public_ip_names=_dedup(pip_names),
        nsg_names=_dedup(nsg_names),
        vnet_names=[],
        disk_names=[],
    )


def delete_unused_proxy_public_ips(
    *,
    subscription_id: str,
    credential=None,
    compute_client=None,
    network_client=None,
    name_prefix: str = "pip-proxy-",
    max_workers: int = 10,
) -> List[str]:
    """
    Deletes proxy public IPs by name prefix unless a currently running VM uses them.
    """
    if compute_client is None or network_client is None:
        if credential is None:
            credential = DefaultAzureCredential()
        if compute_client is None:
            compute_client = ComputeManagementClient(credential, subscription_id)
        if network_client is None:
            network_client = NetworkManagementClient(credential, subscription_id)

    protected_public_ips = _running_vm_public_ip_keys(compute_client, network_client)
    matched: List[Tuple[str, str, str]] = []

    for public_ip in network_client.public_ip_addresses.list_all():
        pip_name = getattr(public_ip, "name", None)
        pip_id = getattr(public_ip, "id", None)
        if not pip_name or not pip_id:
            continue
        if not pip_name.lower().startswith(name_prefix.lower()):
            continue

        rg = _resource_group_from_id(pip_id)
        if (rg.lower(), pip_name.lower()) in protected_public_ips:
            continue

        matched.append((pip_id, pip_name, rg))

    if not matched:
        return []

    worker_count = max(1, min(max_workers, len(matched)))
    deleted_public_ip_ids: List[str] = []
    errors: List[str] = []

    def _delete_one(pip_id: str, pip_name: str, rg: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            public_ip = network_client.public_ip_addresses.get(rg, pip_name)
            nic_ref = _public_ip_nic_ref(public_ip)
            if nic_ref:
                nic_rg, nic_name = nic_ref
                if nic_name.lower().startswith("nic-proxy-"):
                    _remove_public_ip_from_nic(network_client, nic_rg, nic_name, pip_id)

            network_client.public_ip_addresses.begin_delete(rg, pip_name).result()
            return pip_id, None
        except ResourceNotFoundError:
            return pip_id, None
        except Exception as e:
            return None, f"{pip_name}: {e}"

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Deleting unused proxy public IPs", total=len(matched))
        if worker_count == 1:
            for pip_id, pip_name, rg in matched:
                progress.update(task_id, description=f"Deleting Public IP: {pip_name}")
                deleted_id, err = _delete_one(pip_id, pip_name, rg)
                if deleted_id:
                    deleted_public_ip_ids.append(deleted_id)
                if err:
                    errors.append(err)
                progress.advance(task_id, 1)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_public_ip = {
                    executor.submit(_delete_one, pip_id, pip_name, rg): pip_name
                    for pip_id, pip_name, rg in matched
                }

                for future in as_completed(future_to_public_ip):
                    pip_name = future_to_public_ip[future]
                    try:
                        deleted_id, err = future.result()
                        if deleted_id:
                            deleted_public_ip_ids.append(deleted_id)
                        if err:
                            errors.append(err)
                            progress.update(task_id, description=f"Failed Public IP: {pip_name}")
                        else:
                            progress.update(task_id, description=f"Deleted Public IP: {pip_name}")
                    except Exception as e:
                        errors.append(f"{pip_name}: {e}")
                        progress.update(task_id, description=f"Failed Public IP: {pip_name}")
                    finally:
                        progress.advance(task_id, 1)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(
            f"Failed to delete {len(errors)} of {len(matched)} public IP(s). First errors: {preview}"
        )

    return deleted_public_ip_ids


def delete_unused_proxy_public_ips_for_cleanup(*, max_workers: int = 10) -> List[str]:
    credential, subscription_id = get_azure_context()
    return delete_unused_proxy_public_ips(
        subscription_id=subscription_id,
        credential=credential,
        name_prefix="pip-proxy-",
        max_workers=max_workers,
    )


def delete_unused_proxy_nsgs(
    *,
    subscription_id: str,
    credential=None,
    compute_client=None,
    network_client=None,
    name_prefix: str = "nsg-proxy-",
    max_workers: int = 10,
) -> List[str]:
    """
    Deletes proxy NSGs by name prefix unless a currently running VM uses them.
    """
    if compute_client is None or network_client is None:
        if credential is None:
            credential = DefaultAzureCredential()
        if compute_client is None:
            compute_client = ComputeManagementClient(credential, subscription_id)
        if network_client is None:
            network_client = NetworkManagementClient(credential, subscription_id)

    protected_nsgs = _running_vm_nsg_keys(compute_client, network_client)
    matched: List[Tuple[str, str, str]] = []

    for nsg in network_client.network_security_groups.list_all():
        nsg_name = getattr(nsg, "name", None)
        nsg_id = getattr(nsg, "id", None)
        if not nsg_name or not nsg_id:
            continue
        if not nsg_name.lower().startswith(name_prefix.lower()):
            continue

        rg = _resource_group_from_id(nsg_id)
        if (rg.lower(), nsg_name.lower()) in protected_nsgs:
            continue

        matched.append((nsg_id, nsg_name, rg))

    if not matched:
        return []

    worker_count = max(1, min(max_workers, len(matched)))
    deleted_nsg_ids: List[str] = []
    errors: List[str] = []

    def _delete_one(nsg_id: str, nsg_name: str, rg: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            _detach_nsg_from_proxy_nics(network_client, rg, nsg_id)
            network_client.network_security_groups.begin_delete(rg, nsg_name).result()
            return nsg_id, None
        except ResourceNotFoundError:
            return nsg_id, None
        except Exception as e:
            return None, f"{nsg_name}: {e}"

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Deleting unused proxy NSGs", total=len(matched))
        if worker_count == 1:
            for nsg_id, nsg_name, rg in matched:
                progress.update(task_id, description=f"Deleting NSG: {nsg_name}")
                deleted_id, err = _delete_one(nsg_id, nsg_name, rg)
                if deleted_id:
                    deleted_nsg_ids.append(deleted_id)
                if err:
                    errors.append(err)
                progress.advance(task_id, 1)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_nsg = {
                    executor.submit(_delete_one, nsg_id, nsg_name, rg): nsg_name
                    for nsg_id, nsg_name, rg in matched
                }

                for future in as_completed(future_to_nsg):
                    nsg_name = future_to_nsg[future]
                    try:
                        deleted_id, err = future.result()
                        if deleted_id:
                            deleted_nsg_ids.append(deleted_id)
                        if err:
                            errors.append(err)
                            progress.update(task_id, description=f"Failed NSG: {nsg_name}")
                        else:
                            progress.update(task_id, description=f"Deleted NSG: {nsg_name}")
                    except Exception as e:
                        errors.append(f"{nsg_name}: {e}")
                        progress.update(task_id, description=f"Failed NSG: {nsg_name}")
                    finally:
                        progress.advance(task_id, 1)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(
            f"Failed to delete {len(errors)} of {len(matched)} NSG(s). First errors: {preview}"
        )

    return deleted_nsg_ids


def delete_unused_proxy_nsgs_for_cleanup(*, max_workers: int = 10) -> List[str]:
    credential, subscription_id = get_azure_context()
    return delete_unused_proxy_nsgs(
        subscription_id=subscription_id,
        credential=credential,
        name_prefix="nsg-proxy-",
        max_workers=max_workers,
    )


def delete_unused_proxy_vnets(
    *,
    subscription_id: str,
    credential=None,
    compute_client=None,
    network_client=None,
    name_prefix: str = "vnet-proxy-",
    max_workers: int = 10,
) -> List[str]:
    """
    Deletes proxy VNets by name prefix unless a currently running VM uses them.
    """
    if compute_client is None or network_client is None:
        if credential is None:
            credential = DefaultAzureCredential()
        if compute_client is None:
            compute_client = ComputeManagementClient(credential, subscription_id)
        if network_client is None:
            network_client = NetworkManagementClient(credential, subscription_id)

    protected_vnets = _running_vm_vnet_keys(compute_client, network_client)
    matched: List[Tuple[str, str, str]] = []

    for vnet in network_client.virtual_networks.list_all():
        vnet_name = getattr(vnet, "name", None)
        vnet_id = getattr(vnet, "id", None)
        if not vnet_name or not vnet_id:
            continue
        if not vnet_name.startswith(name_prefix):
            continue

        rg = _resource_group_from_id(vnet_id)
        if (rg.lower(), vnet_name.lower()) in protected_vnets:
            continue

        matched.append((vnet_id, vnet_name, rg))

    if not matched:
        return []

    worker_count = max(1, min(max_workers, len(matched)))
    deleted_vnet_ids: List[str] = []
    errors: List[str] = []

    def _delete_one(vnet_id: str, vnet_name: str, rg: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            dependencies = _discover_proxy_nic_dependencies_for_vnet(network_client, rg, vnet_name)
            _delete_resources_parallel(
                names=dependencies.nic_names,
                kind="NIC",
                begin_delete_fn=lambda n: network_client.network_interfaces.begin_delete(rg, n),
                max_workers=max_workers,
            )
            _delete_resources_parallel(
                names=dependencies.public_ip_names,
                kind="Public IP",
                begin_delete_fn=lambda n: network_client.public_ip_addresses.begin_delete(rg, n),
                max_workers=max_workers,
            )
            _delete_resources_parallel(
                names=dependencies.nsg_names,
                kind="NSG",
                begin_delete_fn=lambda n: network_client.network_security_groups.begin_delete(rg, n),
                max_workers=max_workers,
            )
            network_client.virtual_networks.begin_delete(rg, vnet_name).result()
            return vnet_id, None
        except ResourceNotFoundError:
            return vnet_id, None
        except HttpResponseError as e:
            return None, f"{vnet_name}: {e}"
        except Exception as e:
            return None, f"{vnet_name}: {e}"

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Deleting unused proxy VNets", total=len(matched))
        if worker_count == 1:
            for vnet_id, vnet_name, rg in matched:
                progress.update(task_id, description=f"Deleting VNet: {vnet_name}")
                deleted_id, err = _delete_one(vnet_id, vnet_name, rg)
                if deleted_id:
                    deleted_vnet_ids.append(deleted_id)
                if err:
                    errors.append(err)
                progress.advance(task_id, 1)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_vnet = {
                    executor.submit(_delete_one, vnet_id, vnet_name, rg): vnet_name
                    for vnet_id, vnet_name, rg in matched
                }

                for future in as_completed(future_to_vnet):
                    vnet_name = future_to_vnet[future]
                    try:
                        deleted_id, err = future.result()
                        if deleted_id:
                            deleted_vnet_ids.append(deleted_id)
                        if err:
                            errors.append(err)
                            progress.update(task_id, description=f"Failed VNet: {vnet_name}")
                        else:
                            progress.update(task_id, description=f"Deleted VNet: {vnet_name}")
                    except Exception as e:
                        errors.append(f"{vnet_name}: {e}")
                        progress.update(task_id, description=f"Failed VNet: {vnet_name}")
                    finally:
                        progress.advance(task_id, 1)

    if errors:
        preview = "; ".join(errors[:5])
        raise RuntimeError(
            f"Failed to delete {len(errors)} of {len(matched)} VNet(s). First errors: {preview}"
        )

    return deleted_vnet_ids


def delete_unused_proxy_vnets_for_cleanup(*, max_workers: int = 10) -> List[str]:
    credential, subscription_id = get_azure_context()
    return delete_unused_proxy_vnets(
        subscription_id=subscription_id,
        credential=credential,
        name_prefix="vnet-proxy-",
        max_workers=max_workers,
    )
