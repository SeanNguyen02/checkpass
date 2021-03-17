import requests
import hashlib
import sys

# To excute/check your password, type "python checkpass.py " following with the password you want to check.


def request_api_data(hash_head):
    url = 'https://api.pwnedpasswords.com/range/' + hash_head
    respond = requests.get(url)
    if respond.status_code != 200:
        raise RuntimeError(f'Error fetching: {respond.status_code}, check the API and try again')
    return respond


def password_count(respond, hash_tail):
    respond = (line.split(':') for line in respond.text.splitlines())
    for tail, count in respond:
        if tail == hash_tail:
            return count
    return 0


def password_check(password):
    hash_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_head, hash_tail = hash_password[:5], hash_password[5:]
    respond = request_api_data(hash_head)
    return password_count(respond, hash_tail)


def main(args):
    for password in args:
        count = password_check(password)
        if count:
            print(f'{password} was found {count} time(s). You should change your password')
        else:
            print(f'{password} was NOT found, great job')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
