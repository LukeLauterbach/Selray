from typing import Optional, List, Dict
from .AzureAuth import get_azure_context, make_azure_clients


def _resource_group_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Could not parse resource group from id: {resource_id}")


def list_selray_vms(
    *,
    subscription_id = '',
    compute_client = '',
    tag_key: str = "purpose",
    tag_value: str = "selray",
    owner_tag_key: str = "owner",
    owner: Optional[str] = None,
    print_output: bool = True,
) -> List[Dict[str, str]]:
    """
    Lists all VMs with tag_key=tag_value (default: purpose=selray).

    If `owner` is provided, only VMs with owner_tag_key=owner are listed.

    Returns a list of dicts with keys:
      - name
      - resource_group
      - location
      - id
      - tags
    """

    if not subscription_id and not compute_client:
        subscription_id, credential = get_azure_context()
    if not compute_client:
        _, _, _, compute_client = make_azure_clients(subscription_id)

    results: List[Dict[str, str]] = []

    for vm in compute_client.virtual_machines.list_all():
        vm_tags = vm.tags or {}
        vm_name = vm.name
        vm_id = vm.id

        if not vm_name or not vm_id:
            continue

        # Must have the selray tag
        if vm_tags.get(tag_key) != tag_value:
            continue

        # Optional owner filter
        if owner is not None and vm_tags.get(owner_tag_key) != owner:
            continue

        rg = _resource_group_from_id(vm_id)

        entry = {
            "name": vm_name,
            "resource_group": rg,
            "location": vm.location,
            "id": vm_id,
            "tags": vm_tags,
        }
        results.append(entry)

        if print_output:
            if owner is not None:
                print(
                    f"- {vm_name}  (RG={rg}, location={vm.location}, owner={vm_tags.get(owner_tag_key)})"
                )
            else:
                print(
                    f"- {vm_name}  (RG={rg}, location={vm.location}, owner={vm_tags.get(owner_tag_key, 'unknown')})"
                )

    if print_output:
        print(f"\nTotal matched VMs: {len(results)}")

    return results

if __name__ == "__main__":
    list_selray_vms()
