from sys import exit

def import_txt_file(filename):
    data = []
    with open(filename, "r", encoding='utf-8', errors='ignore') as file:
        for line in file:
            data.append(line.rstrip())
    return data


def import_csv_file(filename):
    data = []
    with open(filename, "r", encoding='utf-8', errors='ignore') as file:
        for line in file:
            line = line.rstrip()
            if "," in line:
                line = line.split(",")
                line = f"{line[0]}:{line[1:]}"
            data.append(line)
    return data


def process_file(filenames):
    print(filenames)
    file_contents = []
    if not filenames:
        return False

    if "," in filenames:
        filenames = filenames.split(",")
        for filename in filenames:
            file_contents.extend(parse_filename(filename))
    else:
        file_contents = parse_filename(filenames)
    print(file_contents)
    return file_contents  # If it isn't a file, just return the value

def parse_filename(filename):
    if filename.endswith(".txt"):
        file_contents = import_txt_file(filename)
    elif filename.endswith(".csv"):
        file_contents = import_csv_file(filename)
    else:
        file_contents = [filename]

    return file_contents