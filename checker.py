import argparse
import json
import logging
import socket
import subprocess
from datetime import datetime

import requests
import pythonping
from pysnmp.hlapi import (CommunityData, ContextData, ObjectIdentity,
                          ObjectType, SnmpEngine, UdpTransportTarget, getCmd)

# Improved logging setup
logging.basicConfig(filename='connection_checker.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from JSON file
def load_config(config_file='config.json'):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            
            # Validate configuration keys
            expected_keys = {"url", "verify_ssl", "host", "tcp_host", "tcp_port", 
                             "icmp_host", "snmp_host", "snmp_port", "snmp_community", "snmp_oid"}
            if not expected_keys.issubset(config.keys()):
                raise ValueError("Missing one or more required config keys")
            
            return config
    except (FileNotFoundError, ValueError) as e:
        logging.error(f'Error loading configuration: {e}')
        return None

# HTTP Request Function
def http_request(url="http://www.google.com", verify_ssl=True):
    try:
        response = requests.get(url, timeout=5, verify=verify_ssl)
        return response.status_code == 200
    except requests.RequestException as e:
        logging.error(f'HTTP request error: {e}')
        return False

# DNS Lookup Function
def dns_lookup(domain="google.com"):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror as e:
        logging.error(f'DNS lookup error: {e}')
        return False

# TCP Connection Function
def tcp_connection(host="8.8.8.8", port=53):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except socket.error as e:
        logging.error(f'TCP connection error: {e}')
        return False

# ICMP Echo Function
def icmp_echo(host="8.8.8.8", count=1, timeout=1):
    response = pythonping.ping(host, count=count, timeout=timeout)
    return response.success()

# SNMP Request Function
def snmp_request(host="8.8.8.8", port=161, community='public', oid='1.3.6.1.2.1.1.1.0'):
    try:
        errorIndication, _, _, _ = next(
            getCmd(SnmpEngine(),
                   CommunityData(community, mpModel=0),
                   UdpTransportTarget((host, port)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )
        return not errorIndication
    except Exception as e:
        logging.error(f'SNMP request error: {e}')
        return False

# Argument Parsing Function
def parse_arguments():
    parser = argparse.ArgumentParser(description="Internet Connection Checker")
    parser.add_argument("--config", default="config.json",
                        help="Configuration file")
    return parser.parse_args()

# Main Function
def main():
    try:
        args = parse_arguments()
        config = load_config(args.config)
        if not config:
            return

        results = {
            "http_request": http_request(config.get('url', "http://www.google.com"), config.get('verify_ssl', True)),
            "dns_lookup": dns_lookup(config.get('host', "google.com")),
            "tcp_connection": tcp_connection(config.get('tcp_host', "8.8.8.8"), config.get('tcp_port', 53)),
            "icmp_echo": icmp_echo(config.get('icmp_host', "8.8.8.8"), count=config.get('icmp_count', 1), timeout=config.get('icmp_timeout', 1)),
            "snmp_request": snmp_request(config.get('snmp_host', "8.8.8.8"), config.get('snmp_port', 161), config.get('snmp_community', 'public'), config.get('snmp_oid', '1.3.6.1.2.1.1.1.0'))
        }

        logging.info(f"Check results: {results}")

        # JSON output
        print(json.dumps(results, indent=4))

        # Summary report
        success_count = sum(1 for result in results.values() if result)
        print(f"Connection check summary: {success_count}/{len(results)} successful")
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
