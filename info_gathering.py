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
#supplying the arguments to the parser
args = argparse.parse_args()

#creating object args to parse the supplied arguments

domain = args.domain
ip = args.shodan

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

try:
    py = whois.whois(domain)

#to query whois database


    print("[+] whois information found....")
    print("Name: {}" .format(py.name))
    print("Email: {}" .format(py.email))
    print("Creation Date: {}" .format(py.creation_date))
    print("Expiration Date: {}" .format(py.expiration_date))
    print("Last Updated: {}" .format(py.last_updated))
    print("Name Servers: {}" .format(py.name_servers))
    print("Status: {}" .format(py.status))
    print("Registrar: {}" .format(py.registrar))
    print("Country: {}" .format(py.country))
    print("City: {}" .format(py.city))
except:
    print("[-] No whois information found....")

#DNS Module

print("[+] Getting DNS information....")

#implementing  dns.resolver library from dnspython

try:
    for a in dns.resolver.resolve(domain,"A"):
        print("A Record: {}" .format(a.to_text()))
    for ns in dns.resolver.resolve(domain,"NS"):
        print("NS Record: {}" .format(ns.to_text()))
    for mx in dns.resolver.resolve(domain,"MX"):
        print("MX Record: {}" .format(mx.to_text()))
    for txt in dns.resolver.resolve(domain,"TXT"):
        print("TXT Record: {}" .format(txt.to_text()))
except:
    print("[-] No DNS information found....")

#Geolocation Module

print("[+] Getting Geolocation information....")

#implementing requests library for web requests
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Geolocation information found....")
    print("IP: {}" .format(response['IPv4']))
    print("Country Code: {}" .format(response['country_code']))
    print("Country Name: {}" .format(response['country_name']))
    print("State: {}" .format(response['state']))
    print("City: {}" .format(response['city']))
    print("Latitude: {}" .format(response['latitude']))
    print("Longitude: {}" .format(response['longitude']))
    print("ISP: {}" .format(response['ISP']))
except:
    print("[-] No Geolocation information found....")

#Shodan Module
#using shodan api key

if ip:
    print("[+] Getting Shodan information....")
    #shodan api key
    api = shodan.Shodan("ScHCj6HocTAhrJXwyHgsKQWRQqlOvSZO")
    try:
        results = api.search(ip)
        print("[+] Shodan information found....")
        print("Results Found: {}" .format(results['total']))
        for result in results['matches']:
            print("IP: {}" .format(result['ip_str']))
            print("Organization: {}" .format(result['org']))
            print("Operating System: {}" .format(result['os']))
            print("Port: {}" .format(result['port']))
            print("Location: {}" .format(result['location']))
            print()

    except:
        print("[-] No Shodan information found....")
