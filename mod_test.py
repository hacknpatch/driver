import random
from threading import Thread
import string


def _rand_string(min_len: int = 0, max_len: int = 200):
    n = random.randint(min_len, max_len)
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def _write_to_file(filename, content):
    try:
        with open(filename, mode='w') as f:
            f.write(content)
    finally:
        print('write exited')


def _read_from_file(filename):
    try:
        with open(filename, mode='rb') as f:
            while data := f.read():
                print(data)
    finally:
        print('read exited')


def main():
    for _ in range(1000):
        workers = [
            Thread(target=_write_to_file,
                   args=('/dev/vencrypt_write', _rand_string())),

            Thread(target=_read_from_file,
                   args=('/dev/vencrypt_read',))
        ]
        [w.start() for w in workers]
        [w.join() for w in workers]


if __name__ == '__main__':
    main()

