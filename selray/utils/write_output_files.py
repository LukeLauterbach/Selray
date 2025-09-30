from os import path
from random import randint

def main(args, results):
    if any(entry.get("RESULT") == "VALID USERNAME" for entry in results):
        write_enum_file(args.file_prefix, results)

    if any(entry.get("RESULT") == "SUCCESS" for entry in results):
        write_creds_file(args.file_prefix, results)


def write_enum_file(file_prefix, results):
    count = 0
    file_name = file_prefix + "userlist_valid.txt"
    file_name = get_unique_filename(file_name)

    with open(file_name, "w") as f:
        for entry in results:
            if entry.get("RESULT") == "VALID USERNAME":
                f.write(entry.get("USERNAME") + "\n")
                count += 1

    if count > 0:
        print(f"\n{count} valid usernames written to {file_name}")


def write_creds_file(file_prefix, results):
    count = 0
    file_name = file_prefix + "valid_creds.txt"
    file_name = get_unique_filename(file_name)

    with open(file_name, "w") as f:
        for entry in results:
            if entry.get("RESULT") == "SUCCESS":
                f.write(f"{entry.get('USERNAME')}:{entry.get('PASSWORD')}\n")
                count += 1

    if count > 0:
        print(f"\n{count} valid {'credentials' if count > 1 else 'credential'} written to {file_name}")



def get_unique_filename(filename, directory="."):
    """
    Check if a file with the given filename exists in the directory.
    If it does, append a random number until a unique name is found.
    """
    base, ext = path.splitext(filename)
    filepath = path.join(directory, filename)

    while path.exists(filepath):
        rand_num = randint(1000, 9999)
        new_filename = f"{base}_{rand_num}{ext}"
        filepath = path.join(directory, new_filename)

    return filepath