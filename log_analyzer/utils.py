import time


def watch_log_file(file_path):

    with open(file_path, "r") as file:

        file.seek(0, 2)

        while True:

            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            yield line.strip()