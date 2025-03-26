import sys

import whois
import dns.resolver
import shodan
import requests
import argparse
import socket
argparse = argparse.ArgumentParser(description="Information Gathering Tool",usage="python3 info_gathering.py -d DOMAIN [-s IP]")

#argparse is object of ArgumentParser class
#The items inside brackets are optional for help purpose
argparse.add_argument("-d","--domain",help="Domain name to gather information")
argparse.add_argument("-s","--shodan",help="Enter the IP address to get Shodan information")
argparse.add_argument("-o","--output",help="Output the results to a file")
#supplying the arguments to the parser
args = argparse.parse_args()

#creating object args to parse the supplied arguments

domain = args.domain
ip = args.shodan
output = args.output

print("""
██████╗ ███████╗ █████╗ ██╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ███████║██║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗██║  ██║███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

Real Recon by RealSec Labs                      https://github.com/realseclabs/real-recon
Developed by: Glan Dsouza                       http://github.com/glanloyand
""")

#providing the domain and ip to the variables
print("[+] Getting whois information....")
#using whois library,creating instance
whois_result = ""
try:
    py = whois.whois(domain)

#to query whois database


    whois_result += "[+] whois information found...." + "\n"
    whois_result += "Name: {}" .format(py.name) + "\n"
    whois_result += "Email: {}" .format(py.email) + "\n"
    whois_result += "Creation Date: {}" .format(py.creation_date) + "\n"
    whois_result += "Expiration Date: {}" .format(py.expiration_date) + "\n"
    whois_result += "Last Updated: {}" .format(py.last_updated) + "\n"
    whois_result += "Name Servers: {}" .format(py.name_servers) + "\n"
    whois_result += "Status: {}" .format(py.status) + "\n"
    whois_result += "Registrar: {}" .format(py.registrar) + "\n"
    whois_result += "Country: {}" .format(py.country) + "\n"
    whois_result += "City: {}" .format(py.city) + "\n"
except:
    whois_result += "[-] No whois information found...." + "\n"

print(whois_result)
#DNS Module

print("[+] Getting DNS information....")

#implementing  dns.resolver library from dnspython
dns_result = ""
try:
    dns_result += "[+] Getting DNS information...." + "\n"
    for a in dns.resolver.resolve(domain,"A"):
        dns_result += "A Record: {}" .format(a.to_text()) + "\n"
    for ns in dns.resolver.resolve(domain,"NS"):
        dns_result += "NS Record: {}" .format(ns.to_text()) + "\n"
    for mx in dns.resolver.resolve(domain,"MX"):
        dns_result += "MX Record: {}" .format(mx.to_text()) + "\n"
    for txt in dns.resolver.resolve(domain,"TXT"):
        dns_result += "TXT Record: {}" .format(txt.to_text()) + "\n"
except:
    dns_result += "[-] No DNS information found...." + "\n"
print(dns_result)
#Geolocation Module

print("[+] Getting Geolocation information....")

#implementing requests library for web requests
geolocation_results = ""
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    geolocation_results += "[+] Geolocation information found...." + "\n"
    geolocation_results += "IP: {}" .format(response['IPv4']) + "\n"
    geolocation_results += "Country Code: {}" .format(response['country_code']) + "\n"
    geolocation_results += "Country Name: {}" .format(response['country_name']) + "\n"
    geolocation_results += "State: {}" .format(response['state']) + "\n"
    geolocation_results += "City: {}" .format(response['city']) + "\n"
    geolocation_results += "Latitude: {}" .format(response['latitude']) + "\n"
    geolocation_results += "Longitude: {}" .format(response['longitude'])  + "\n"
    geolocation_results += "ISP: {}" .format(response['ISP']) + "\n"
except:
    geolocation_results += "[-] No Geolocation information found...." + "\n"
print(geolocation_results)

#Shodan Module
#using shodan api key

if ip:
    print("[+] Getting Shodan information....")
    #shodan api key
    api = shodan.Shodan("ScHCj6HocTAhrJXwyHgsKQWRQqlOvSZO")
    shodan_results = ""
    try:
        results = api.search(ip)
        shodan_results += "[+] Shodan information found...." + "\n"
        print("Results Found: {}" .format(results['total']))
        for result in results['matches']:
            shodan_results += "IP: {}" .format(result['ip_str']) + "\n"
            shodan_results += "Organization: {}" .format(result['org']) + "\n"
            shodan_results += "Operating System: {}" .format(result['os']) + "\n"
            shodan_results += "Port: {}" .format(result['port']) + "\n"
            shodan_results += "Location: {}" .format(result['location']) + "\n"
            print()
    except:
        shodan_results += "[-] No Shodan information found...." + "\n"
    print(shodan_results)

#Output Module
if(output):
    print("[+] Writing output to file....")
    with open(output,"w") as file:
        file.write(whois_result)
        file.write(dns_result)
        file.write(geolocation_results)
        if ip:
            file.write(shodan_results)
    print("[+] Output written to file....")