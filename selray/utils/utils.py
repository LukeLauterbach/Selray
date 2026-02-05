import sys
from . import aws, rotate_ip_if_needed
from datetime import datetime, timedelta
import pause
import os
import toml
import importlib.resources
from . import update, attempt_login, create_selray_vm, delete_vm_by_name
import subprocess
from pathlib import Path
from importlib import resources as importlib_resources


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def alternate_modes(args):
    if args.proxy_clean:
        destroy_proxies(args)
        exit()
    elif args.proxy_list:
        print("Getting list of proxies...\n")
        list_proxies(args)
        exit()
    elif args.update:
        update.self_update(args.update)
        exit()
    elif args.list_modes:
        list_modes()
        exit()


def load_mode_config(args, mode_dir='selray/modes'):
    """
    Loads mode configuration from a TOML file into the args namespace if not already specified.
    """
    try:
        with importlib.resources.files("selray.modes").joinpath(f"{args.mode.lower()}.toml").open("r") as f:
            config = toml.load(f)
    except FileNotFoundError:
        config_path = os.path.join(mode_dir, f"{args.mode.lower()}.toml")
        with open(config_path, 'r', encoding='utf-8') as f:
            config = toml.load(f)

    for key, value in config.items():
        if not getattr(args, key, None):
            setattr(args, key, value)


def list_in_string(string_to_check="", list_to_compare=None):
    # Return True if any string from ``list_to_compare`` exists in ``string_to_check``.
    if not list_to_compare:
        return False
    for comparison_string in list_to_compare:
        if comparison_string.lower() in string_to_check.lower():
            return True
    return False


def prepare_invalid_username(invalid_username=None):
    final_list = ["couldn't find an account with that username", "this username may be incorrect"]
    if invalid_username:
        invalid_username = invalid_username.split(",")
        final_list.extend(invalid_username)
    return final_list


def prepare_passwordless(passwordless_auth=None):
    final_list = ["Get a code to sign in", "Complete sign-in using your passkey"]
    if passwordless_auth:
        the_list = passwordless_auth.split(",")
        final_list.extend(the_list)
    return final_list


def prepare_lockout(lockout_messages=None):
    final_list = ["account has been locked out", "too many login attempts", "your account is temporarily locked"]
    if lockout_messages:
        invalid_username = lockout_messages.split(",")
        final_list.extend(invalid_username)
    return final_list


def prepare_url(url=""):
    if not url:
        return False
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"  # TODO Check URL and allow http://, if that's all that's supported.

    return url


def prepare_usernames(usernames=None, domain="", domain_after=False, domain_before=False):
    if not domain and not domain_after and not domain_before:
        return usernames

    i = 0
    while i < len(usernames):
        if "/" in usernames[i] or "@" in usernames[i]:  # If the domain is already in the username, ignore the domain
            i += 1
            continue

        if domain_after:
            usernames[i] = f"{usernames[i]}@{domain_after}"
        elif domain_before:
            usernames[i] = f"{domain_before}\\{usernames[i]}"
        else:
            usernames[i] = f"{domain}/{usernames[i]}"

        i += 1

    return usernames


def print_ending(results):
    print(f"\nPassword spraying completed at {datetime.now().strftime('%m/%d/%Y %H:%M')}")

    success_count = sum(1 for entry in results if entry and entry.get('RESULT') == 'SUCCESS')
    if success_count:
        print(f"Valid Credentials Found: {success_count}")
        for credential in results:
            if credential and credential.get('RESULT') == 'SUCCESS':
                print(f"{credential['USERNAME']} - {credential['PASSWORD']}")
    else:
        print("No valid credentials found.")


def import_txt_file(filename):
    data = []
    with open(filename, "r", encoding='utf-8', errors='ignore') as file:
        for line in file:
            data.append(line.rstrip())
    return data


def process_file(filename):
    if not filename:
        return False
    if filename.endswith(".txt"):
        return import_txt_file(filename)
    elif filename.endswith(".csv"):
        print("ERROR - CSVs are currently not supported.")
        sys.exit()
    else:
        return [filename]  # If it isn't a file, just return the value


def prepare_success_fail(success="", fail=""):
    if success:
        success = success.split(",")
        fail = []
    elif fail:
        fail = fail.split(",")
        success = []

    return fail, success


def prepare_proxies(ec2, args):
    proxies = []
    if args.proxies:
        manual_proxies = process_file(args.proxies)
        if not manual_proxies:
            manual_proxies = args.proxies.split(",")

        for manual_proxy in manual_proxies:
            proxies.append({"type": "MANUAL", "ip": "", "id": None, "url": manual_proxy})

    threads_needed = args.threads
    threads_needed -= len(proxies)

    if args.azure:
        if threads_needed >= 6:
            azure_threads = 3
        elif args.aws:
            azure_threads = int(threads_needed / 2)
        else:
            azure_threads = threads_needed
        threads_needed -= azure_threads
        proxies.extend(azure_proxy.create_proxies(azure_threads))

    if args.aws:
         proxies.extend(aws.proxy_setup(ec2, threads_needed))

    if not proxies:
        proxies = [{"type": None, "ip": None, "id": None, "url": None} for _ in range(args.threads)]

    return proxies  # Proxies will always be a list of dicts.


def destroy_proxies(args):
    from selray.utils import delete_selray_vms
    if args.azure:
        delete_selray_vms()


def list_proxies(args):
    from selray.utils import list_selray_vms
    list_selray_vms()


def print_beginning(args, version=None):
    # Calculate the length of the spray
    total_minutes = len(args.passwords) * args.delay
    days = total_minutes // (24 * 60)
    hours = (total_minutes % (24 * 60)) // 60
    minutes = total_minutes % 60
    if days == 0:
        spray_duration = "{:02d}:{:02d}".format(hours, minutes)
    else:
        spray_duration = "{:02d} {:02d}:{:02d}".format(days, hours, minutes)

    print(f"{Colors.HEADER}{Colors.BOLD}Selray{Colors.END}")
    print(f"Author:  Luke Lauterbach (Sentinel Technologies)")
    print(f"Version: {version}\n")

    print(f"{'Username Count:':<28}{len(args.usernames)}")
    print(f"{'Password Count:':<28}{len(args.passwords)}")
    print(f"{'Total Login Attempts:':<28}{(len(args.usernames) * len(args.passwords))}")
    print(f"{'Approximate Spray Duration:':<28}{spray_duration}")
    print(f"{'URL:':<28}{args.url}")
    if args.domain and args.domain_after:
        print(f"{'Domain:':<28}@{args.domain}")
    elif args.domain and not args.domain_after:
        print(f"{'Domain:':<28}{args.domain}/")
    print(f"{'Username Field:':<28}{args.username_field}")
    print(f"{'Password Field:':<28}{args.password_field}")
    if args.success:
        print(f"{'Success Condition:':<28}{args.success}")
    elif args.fail:
        print(f"{'Failure Condition:':<28}{args.fail}")
    print(f"{'Invalid Username Condition:':<28}{args.invalid_username}")
    print(f"{'Lockout Condition:':<28}{args.lockout}")
    print(f"{'Threads:':<28}{args.threads}")
    print(f"{'Delay:':<28}{args.delay}\n")


def perform_spray(spray_config, credentials, queue):
    results = []
    vm_url = ""
    spray_num_with_current_ip = 0
    if spray_config.azure:
        vm_name, vm_url, vm_ip, nic_name, credential, network_client, compute_client, owner = create_selray_vm(spray_config.azure_resource_group)
    for credential in credentials:
        spray_config.username = credential['USERNAME']
        spray_config.password = credential['PASSWORD']

        # `attempt_login` returns a dictionary with:
        #   - USERNAME
        #   - PASSWORD
        #   - RESULT: one of ["INVALID USERNAME", "LOCKED", "PASSWORDLESS", "VALID USERNAME", "ERROR", "SUCCESS", "FAILURE"]
        result = attempt_login.main(spray_config, vm_url)

        if spray_config.azure:
            # If an error was returned, force a proxy IP change
            if result.get("RESULT") == "ERROR":
                spray_num_with_current_ip = 10000

            # Force rotate on navigation/proxy errors to recover quickly.
            spray_num_with_current_ip, new_ip, new_url, _ = rotate_ip_if_needed(
                spray_config.azure_resource_group,
                vm_name,
                spray_config.num_sprays_per_ip,
                spray_num_with_current_ip,
                network_client,
                compute_client,
                nic_name,
                spray_config.azure_location,
            )

            # rotate_ip_if_needed can return null urls and ips, so this just ensures we don't set them to null
            if new_url:
                vm_url = new_url
            if new_ip:
                vm_ip = new_ip

            # If an error was encountered, try to log in again
            if result.get("RESULT") == "ERROR":
                result = attempt_login.main(spray_config, vm_url)

        results.append(result)

    queue.put(results)
    delete_vm_by_name(spray_config.azure_resource_group, vm_name)


def credential_stuffing(spray_config, args):
    from . import credential_stuffing
    from .spray import launch_spray_processes
    results = []

    credentials = credential_stuffing.split_username_password(args.usernames)
    credentials = credential_stuffing.assign_spray_identifier(credentials)

    stuffing_attempt = 1
    num_stuffing_attempts = max(d['ATTEMPT'] for d in credentials)

    while stuffing_attempt <= num_stuffing_attempts:
        next_start_time = datetime.now() + timedelta(minutes=args.delay)  # Check when the next spray should run
        print(f"Beginning stuffing attempt {stuffing_attempt} of {num_stuffing_attempts}.")

        user_chunks = credential_stuffing.split_users_into_chunks(credentials, stuffing_attempt, args.threads)
        results.extend(launch_spray_processes(spray_config, user_chunks))

        # Check to see if the process is at the end. If not, wait the specified time.
        if stuffing_attempt < num_stuffing_attempts:
            print(f"Stuffing attempt {stuffing_attempt} of {num_stuffing_attempts} complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next stuffing attempt.")
            if any(entry['RESULT'] == 'SUCCESS' for entry in results):
                print("Valid Credentials Found:")
                for entry in results:
                    if entry['RESULT'] == 'SUCCESS':
                        print(f"{entry['USERNAME']} - {entry['PASSWORD']}")
                print()
            pause.until(next_start_time)

        else:
            print(
                f"Spray of password {stuffing_attempt} of {num_stuffing_attempts} complete. All passwords complete.")
        stuffing_attempt += 1

    return results

def initialize_playwright():
    patchright_cmd = Path(sys.executable).parent / "patchright"

    # Only needed for the first time run, but won't error on later runs
    subprocess.run([patchright_cmd, "install"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def list_modes(output_to_terminal=True):
    base = importlib_resources.files("selray").joinpath("modes")
    filenames = [p.name for p in base.iterdir() if p.is_file()]
    filenames = [os.path.splitext(n)[0] for n in filenames]
    filenames = sorted(filenames)

    if output_to_terminal:
        print("Available Modes:")
        for filename in filenames:
            print(f"  • {filename.removesuffix('.toml')}")

    return filenames
