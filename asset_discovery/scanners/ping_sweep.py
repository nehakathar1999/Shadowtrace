import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from config.settings import settings


def ping_host(ip):

    flag = "-n" if platform.system().lower() == "windows" else "-c"

    try:
        subprocess.check_output(
            ["ping", flag, "1", "-w", "1000", str(ip)],
            stderr=subprocess.DEVNULL
        )
        return str(ip)

    except:
        return None


def threaded_ping_sweep(ip_list):

    active_hosts = []

    with ThreadPoolExecutor(max_workers=settings.MAX_THREADS) as executor:

        futures = [executor.submit(ping_host, ip) for ip in ip_list]

        for future in as_completed(futures):

            result = future.result()

            if result:
                active_hosts.append(result)

    return active_hosts