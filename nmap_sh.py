import socket
import threading
import nmap

print("""
                                      *%@@@@@@@@@@@@@@@@%#*+:  
                                  :#@@@@#-+.-==:--=-#+%+@@@@@@%-  
                                 =@@@+---:-=---:..:-=--:.-+*=%@@#-  
                                -%@@#::..=.+..+.-+-:.+..*--.+.:#@@@=..  
                               #%=%:+-=#=+.*:-.=:+-::.*.*:=. :.::*=@@%*.  
                               %@@+-=.---==-.--=::-:-=--:.:.     ...:+@@@:  
                              #@@=+.======:-=-:=::.:--=::            .-*@%=.  
                            -%@@@@@@#:=%#--:--.::::--:..              .#@@@-  
                           *@@@@@@@@@@@@##@@:+:=-=-:-..               ..-%@@#  
                          -@@@@@@@@@@@@@@@@#*#%+-=.==:.                  .:%@@+  
                         .+@@@@@@@@@@@@@@@@%:=%-:.:--:.                   .=@@%:  
                         :@@@@@@@@@@@@@@@@@@@@#=*--+*:..                  ..=@@@=  
                        -@@@@@@@@@@@@@@@@@@@@@@@@*-:-.+.                     .%@*  
                        *@@@@@@@@@@@@@@@@@@@@@@@@@*-=-:::..                  .+@*  
                       :@@@@@@@@@@@@@@@@@@@@@@@@@@*=+:::.:.                  .+@*  
                       #@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.+.=-#                 .%@*  
                       #@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:=.=--:.+:-..          -@@@=  
                       %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+:::.-.::-::*+++:     =@@#  
                        %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+:::.-.::-::*+++:     =@@#
                        @@@@@@@@@@@%@@@@@@@@@@@@@@@@@%.:.::=..:. =%*.*%%#*. .:@%:  
                        *@@@@@@@%-%###%%++@@@@@@@@@@@@%.*..       .+@@@@-:.  .%@*  
                         :%@@@@@%-#@@@@#%%-*@@@@@@@@@@#:...+:+#+... .:+:.+*:..+@#  
                         .:%@@@@@@@@@@@@@%#%@@@@@@@@%-+.#@@@@@@@@%=  ...@@@@#..*%:  
                           =@@@@@@@@@@@@@@@@@@@@@@@@*::%@@@@@@@@@%-   .:@%@#..=%%:  
                            :%@@@@@@@@@@@@@@@@@@%%%=::%@@%#%@@@@@+.   .:*:@* .#@*  
                              %@@@@@@@@@@@@@@@@@*:=.*#:%%%:-%@@@@#.      .##::#%-  
                               %@@@@@@@@@@@@@@@@*.-*++.:..-@%@@%+  :%%%#:... :@%:  
                               =@@@@@@@@@@@@@@@@@@@@#*:-. ..-++:. -#@@*=.    :@%:  
                                 =%@@@@@@@@@@@@@@@@@@@@#%:*:.      =@@@-.  ..-%@#  
                                 =#@@@@@@@@@%%@@@@@@@@@@%:=+     =#-%-. :%@@@+.  
                                       -%@@@@-*@@@@@@@@@@@@%#...  .......#@%+:  
                                        %@@%:*%@@@@@@@@@@@*-**%-.    ....@@+  
                                       -@@@@#-%@@@@@@@@@@@@==-#*%:...-:.:@@=  
                                        +@@%-#@@*-@@@@@@@@@%%@@@#%:-=--..@@:  
                                        -%@%#@#-+@@@@@@@@%%@@%=+--.::..@@:  
                                         =%@*==++#**@%*%##+.*@@%*%#+..-@@.  
                                           #@@@@@%:*-*:%+==:**#%+. ..-@%:  
                                             -%@@@@@%@%+::-.....  .:*@#-  
                                               .=#%@@@@@%--::     .:%%=.  
                                                     -%@@@#:-:...:=@@#  
                                                         =%@@@@@@@@%-  
                                                            -+=-
                        -----------------------------------------------------------------------------------   
                                                        By: Ammar
                                                      Insta: 3wq.7
                        -----------------------------------------------------------------------------------                               
""")


def get_service_name(port, proto):
    try:
        service_name = socket.getservbyport(port, proto)
    except OSError:
        service_name = "unknown"
    return service_name


def scan_port(ip, port, proto):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service_name = get_service_name(port, proto)
            print(f"{port}/{proto}  open  {service_name}")
        else:
            return
    except socket.error:
        pass
    except socket.timeout:
        print(f"Port {port}/{proto} timed out")


def scan_ports_nmap(ip, ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, ports, arguments='-v')

        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = list(nm[host][proto].keys())
                for port in lport:
                    state = nm[host][proto][port].get('state', 'unknown')
                    service_name = nm[host][proto][port].get('name', 'unknown')
                    version = nm[host][proto][port].get('version', 'unknown')

                    print(f"\nPort {port}/{proto} is {state}")
                    print(f"  Service: {service_name}")
                    print(f"  Version: {version}")

                    if 'script' in nm[host][proto][port]:
                        for script_name, script_output in nm[host][proto][port]['script'].items():
                            print(f"  Script {script_name} Output: {script_output}")

    except Exception as e:
        print(f"Error during Nmap scan: {e}")


def scan_ports(ip, specific_ports=None, detailed=False):
    threads = []
    if specific_ports:
        for port in specific_ports:
            thread = threading.Thread(target=scan_port, args=(ip, port, 'tcp'))
            threads.append(thread)
            thread.start()
    else:
        for port in range(1, 446):
            thread = threading.Thread(target=scan_port, args=(ip, port, 'tcp'))
            threads.append(thread)
            thread.start()

        if detailed:
            scan_ports_nmap(ip, '1-445')

    for thread in threads:
        thread.join()


def main():
    while True:
        ip = input("Enter Target IP: ")
        print("--------------------------------------------------------------------------------------------")
        print("Target IP is", ip)

        try:
            socket.inet_aton(ip)
            break
        except socket.error:
            print("Invalid IP address.")
            continue

    resp = input("""
             1) Scan all ports
             2) Scanning all ports with more informations:
                     """)

    if resp == "1":
        print("Scanning all ports:")
        scan_ports(ip, detailed=False)
    elif resp == "2":
        print("Scanning all ports with detailed information:")
        scan_ports(ip, detailed=True)
    else:
        print("Invalid selection. Exiting.")


if __name__ == "__main__":
    main()
