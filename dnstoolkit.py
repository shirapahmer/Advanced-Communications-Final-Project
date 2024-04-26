import scapy.packet
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1, sniff
import ipaddress
import socket
import os
from pathlib import Path
import sys

'''
@Author: Shira Pahmer, 575285308
DNSTOOLKIT Final Project
Implementation of the Dig caa, dnsmap, and whois commands. Takes in domain name parameter from the command line and 
runs dig caa, dnsmap, and whois, respectively, on the domain name
'''

'''
Python implementation of the dig command, specifically for the 'caa' flag of the dig command
Takes in a domain name and returns the caa record for that domain
@param domain = the domain name being queried
'''
def dig_caa(domain):
    # create dns query packet
    packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="CAA"))
    response_pkt = sr1(packet, timeout=3, verbose = False)  # send query and wait for response packet
    caa_list = []
    #if no response received
    if not response_pkt:
        print("No caa record for that domain\n")
        return

    for x in range(response_pkt[DNS].ancount):
        ca_name = (response_pkt[DNS].an[x].rdata.decode()).partition("issue")
        if ca_name[2] != "": caa_list.append(ca_name[2])  # store ca's

    #if received a response but there are no caa records
    if len(caa_list) == 0:
        print("No caa record for that domain\n")
        return
    #else print the caa records
    print("CAA Record:")
    for each in caa_list:
        print(each)
    print()


'''
Python implementation of dnsmap tool that takes a domain name and brute-force searches for ip addresses of many subdomains
and prints the subdomains that exist and their ip address
@:param domain = domain name
'''
def dnsmap(domain):
    #check if valid domain name for dns mapping
    validate = validate_domain_dnsmap(domain)
    if not validate:
        print("[+] error: entered domain is not valid for dnsmap!")
        return

    current_directory = os.path.dirname(os.path.abspath(__file__))
    path_file1 = Path(current_directory) / 'dnsmap.h.txt'
    file1 = open(path_file1)
    for line in file1:
        if '{' in line:  #move iterator to line that starts the prefixes
            for prefixLine in file1:
                newDomain = prefixLine[1:-3] + '.' + domain  #create the new domain with prefix attached
                try:
                    data = socket.gethostbyname_ex(newDomain)  #send domain over socket to receive ip's if existing
                    print_mapped_addr(data, newDomain)  #print the associated ip's
                except:
                    pass
    file1.close()
    #same functionality as previous chunk of code but new prefix wordlist
    path_file2 = Path(current_directory) / 'wordList_TLAs.txt'
    file2 = open(path_file2)
    for line in file2:
        if '# GNUCITIZEN.org' in line:
            for prefixLine in file2:
                newDomain = prefixLine[0:-1] + '.' + domain
            try:
                data = socket.gethostbyname_ex(newDomain)
                print_mapped_addr(data, newDomain)
            except:
                pass
    file2.close()
    print()

'''
Helper function for dnsmap()
takes in the list of domain ip's and prints them in a formatted way
@:param data = list of ip's
@:param domain = the domain name we queried 
'''
def print_mapped_addr(data, domain):
    print(domain)
    for i in range(len(data[2])):
        ip = data[2][i]
        print(f"IP Address #{i + 1}: {ip}")
        internal_flag = ipaddress.ip_address(ip).is_private  #check if ip is internal ip address
    print("[+] warning: internal IP address disclosed\n") if internal_flag else print()

'''
Helper function for dnsmap(). Validates the domain name using the same checks as the actual dnsmap implementation on github
(Not including checks for wildcards)
@:param domain = domain to validate
'''
def validate_domain_dnsmap(domain):
    #smallest valid domain length = 4
    if len(domain) < 4:
        return False
    #must have at least 1 . in domain
    if not '.' in domain:
        return False
    #tld must be between 2 and 6 chars
    tld_index = domain.rfind('.') + 1
    tld = domain[tld_index:]
    if len(tld) < 2 or len(tld) > 6:
        return False

    #valid domain can only contain digits, letters, dot (.) and dash symbol (-)
    for i in range(len(domain)):
        if (not(domain[i] >= '0' and domain[i] <= '9') and
        not(domain[i] >= 'a' and domain[i] <= 'z') and
        not(domain[i] >= 'A' and domain[i] <= 'Z') and
        not(domain[i] >= '-' and domain[i] <= '.')):
            return False

    return True

'''
Python implementation of the whois linux function. Only works for ipv4. Takes in a domain name, finds the correct
whois server to query, then sends the query and prints the response
@:param domain = domain the domain name being queries
@:param server = the server domain name if we are recursively querying
'''
def whois(domain, server=None):
    whois_dict = {}
    current_directory = os.path.dirname(os.path.abspath(__file__))
    path_file = Path(current_directory) / 'whois_servers.txt'
    file = open(path_file)

    #populate dictionary with tld-server name pairs
    for line in file:
        # Split each line of server list into two strings based on the space
        key, value = line.strip().split(' ', 1)
        # Add the key-value pair to the dictionary for easy reference between tld and its server
        whois_dict[key] = value

    # first level whois call to get the server domain name
    if server == None:
        domain_extension = domain.split('.')
        if domain_extension[-1] in whois_dict:
            server = whois_dict[domain_extension[-1]]
        else:
            print("No whois server is known for this kind of object")
            return

    # send dns query to find ip address of tld whois server
    data = socket.gethostbyname_ex(server)
    if data[2][0]:  # if server ip address exists
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((data[2][0], 43))  # connect to the correct server on its whois port
        query = domain + '\r\n'  # create the whois query
        connection.send(query.encode())
        response = ''
        # Send the WHOIS query and receive the response
        packets = sniff(timeout=6)

        # find relevant packets for this query response and print their data
        for each in packets:
            response += printResponse(each)
        print(response)
        # if original response contained another whois server that we need to query
        if ("Registrar WHOIS Server:") in response:
            # Find the index of "Registrar WHOIS Server:"
            index = response.find("Registrar WHOIS Server:")
            # Extract the substring after "Registrar WHOIS Server:"
            substring = response[index + len("Registrar WHOIS Server:"):].split(None, 1)[0].strip()
            if (substring != server):  # if we haven't yet queried that server then send it the query
                whois(domain, substring)
    file.close()


'''
Helper function for whois(). Finds the packets that contain the whois response and extracts their data
@:param pkt the list of packets that were sniffed
@:return the data from the whois response
'''
def printResponse(pkt):
    #if the current packet is from the whois server and has raw data containing the response
    if "TCP" in pkt and pkt[TCP].sport == 43 and isinstance(pkt[TCP].payload, scapy.packet.Raw):
        return pkt[TCP].payload.load.decode()
    return ""

def main(domain):
    print("dig {domain} caa\n".format(domain=domain))
    dig_caa(domain)
    print("dnsmap {domain}\n".format(domain=domain))
    dnsmap(domain)
    print("whois {domain}\n".format(domain=domain))
    whois(domain)

if __name__ == '__main__':
    domain = sys.argv[1]
    main(domain)
