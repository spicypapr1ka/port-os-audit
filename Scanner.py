import nmap
import socket

# The variable nps allows reduced usage of letters in code to
# maintain clean and easy to read code, but also stores
# information relating to the scan.
nps = nmap.PortScanner()

def getIP():
    # getIP asks a user to enter an IP address that will be scanned
    # in hostScan. The IP address is stored in the variable target.
    IP = input("Enter the IP address you wish to scan: ")
    print(f"{IP} will be scanned.")
    print("--------------------")
    return IP

def hostScan(target):
    # The function hostScan takes the target IP address and defines
    # the range of ports to be scanned. 0-1023 was chosen since they
    # are well known and used and the more ports scanned, the longer
    # the ouput wait time. 
    ports = '0-1023'
    nps.scan(hosts=target, ports=ports, arguments='-O')

    for host in nps.all_hosts():
        # This for loop prints the target host and its status
        # (if the host is up or not)
        print(f"For the target host {target}:")
        print(f"Status: {nps[host].state()}")
        for protocol in nps[host].all_protocols():
            # This for loop prints the protocol used by the host's 
            # ports, which is usuallu either TCP or UDP.
            print(f"Protocol: {protocol}")
            print("--------------------")
            allports = sorted(nps[host][protocol].keys())
            for port in allports:
                # This uses both the python-nmap AND built-in socket library. 
                # Socket grabs the service types for the ports found open.
                # Afterward, the ports are printed, their service type is given
                # based on what socket found, and its status is given (open, filtered),
                # and closed ports will NOT print out.
                try:
                    service = socket.getservbyport(port, protocol)
                except:
                    service = "unknown service"
                print(f"Port: {port}")
                print(f"   Service type: {service}")
                print(f"   Status: {nps[host][protocol][port]['state']}")
        print("--------------------")
        if 'osmatch' in nps[host]:
            # This if/else statement tries to grab the operating
            # system of the host using nmap's osmatch. If there is
            # anything detected (multiple may be detected as well),
            # then it will print and will give an accuracy rating.
            for osmatch in nps[host]['osmatch']:
                print(f"Operating System: {osmatch['name']} / Accuracy rating: {osmatch['accuracy']}%")
        else:
            print("OS: not found")
    print("--------------------")
    print("Done.")
                

if __name__ == "__main__":
    target = getIP()
    PortScanning = hostScan(target)
    