import random
from threading import Thread
import string


def _rand_string(min_len: int = 0, max_len: int = 200):
    n = random.randint(min_len, max_len)
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def _write_to_file(filename, content, verbose: bool = False):
    if verbose:
        print(f'write enter {len(content) % 16} {content}')
    try:
        with open(filename, mode='wb') as f:
            f.write(content)
    finally:
        if verbose:
            print('write exited')


def _read_from_file(filename, content, verbose: bool = False):
    if verbose:
        print(f'read enter {len(content) % 16} {content}')
    read = b''
    try:
        with open(filename, mode='rb') as f:

            while r := f.read():
                read += r

            if read != content:
                print(f'{read} != {content}')

    finally:
        if verbose:
            print('read exited')


def main():
    for _ in range(10000):
        text = _rand_string().encode()
        workers = [
            Thread(target=_write_to_file,
                   args=('/dev/vencrypt_write', text)),

            Thread(target=_read_from_file,
                   args=('/dev/vencrypt_read', text))
        ]
        [w.start() for w in workers]
        [w.join() for w in workers]


def play():
    from time import sleep
    text = _rand_string().encode()

    s = Thread(target=_write_to_file,
               args=('/dev/vencrypt_write', text, True))

    r = Thread(target=_read_from_file,
               args=('/dev/vencrypt_read', text, True))

    [w.start() for w in [r, s]]
    [w.join() for w in [r, s]]


if __name__ == '__main__':
    main()
    play()
