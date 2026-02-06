import ssl
import urllib.request
from urllib.error import URLError, HTTPError
import time


def check_proxy_external(proxy_ip: str, proxy_port: int = 3128, timeout: int = 10) -> bool:
    proxy_url = f"http://{proxy_ip}:{proxy_port}"
    test_url = "https://example.com/"

    proxy_handler = urllib.request.ProxyHandler({
        "http": proxy_url,
        "https": proxy_url,
    })

    ssl_context = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)

    opener = urllib.request.build_opener(proxy_handler, https_handler)

    req = urllib.request.Request(
        test_url,
        headers={"User-Agent": "proxy-healthcheck/1.0"},
    )

    try:
        with opener.open(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except (HTTPError, URLError, TimeoutError, ssl.SSLError) as e:
        # print(f"[!] External proxy check failed: {e}")
        return False


def wait_for_proxy_ready(
    proxy_ip: str,
    proxy_port: int = 3128,
    check_interval: int = 5,
    timeout: int = 180,
) -> bool:
    """
    Waits until the proxy is reachable and working.

    - Checks every `check_interval` seconds
    - Gives up after `timeout` seconds
    - Returns True if proxy becomes ready, False otherwise
    """
    start = time.time()
    attempt = 0

    while True:
        attempt += 1
        elapsed = int(time.time() - start)

        if elapsed > timeout:
            print(f"[!] Proxy not ready after {elapsed}s, giving up")
            return False

        #print(f"[.] Proxy check attempt {attempt} (elapsed {elapsed}s)")

        if check_proxy_external(proxy_ip, proxy_port):
            #print(f"[+] Proxy is ready after {elapsed}s")
            return True

        time.sleep(check_interval)


if __name__ == "__main__":
    print(
        check_proxy_external(
            proxy_ip="172.171.194.75",
            proxy_port=3128,
            timeout=10,
        )
    )
