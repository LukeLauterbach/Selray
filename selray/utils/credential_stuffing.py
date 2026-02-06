from collections import defaultdict

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

