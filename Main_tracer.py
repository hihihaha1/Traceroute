import argparse
import sys
import requests
from Support_functions import validate_ip, resolve_dns
from tracert import traceroute
from GUImap import create_map_from_ips

def get_my_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=text")
        if response.status_code == 200:
            return response.text.strip()
        else:
            print("Ошибка получения публичного IP.")
            return None
    except Exception as e:
        print(f"Ошибка запроса публичного IP: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(prog="FlagParser", description="Parsing traceroute's flags")
    parser.add_argument('ip_address', type=str, help="Tracing IP")
    parser.add_argument("-l", "--ttl-visible", action="store_true", help="TTL Visible flag")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Max hops N limit")
    parser.add_argument('-6', '--ipv6', action="store_true", help="Enable IPv6 Traceroute")
    parser.add_argument("-f", "--start-ttl", type=int, default=1, help="Start tracing for N ttl to max hops")
    parser.add_argument("-w", "--waittime", type=int, default=2, help="Set N timeout")
    args = parser.parse_args()

    use_ipv6 = args.ipv6

    if validate_ip(args.ip_address):
        ip = args.ip_address
    else:
        ip = resolve_dns(args.ip_address, ipv6=use_ipv6)
        if not ip:
            print("Ошибка: Не удалось разрешить доменное имя.")
            sys.exit(1)

    hop_ips = traceroute(ip, max_hops=args.max_hops, timeout=args.waittime,
                         ipv6=use_ipv6, start_ttl=args.start_ttl, ttl_visible=args.ttl_visible)

    my_ip = get_my_public_ip()
    if my_ip:
        hop_ips.insert(0, my_ip)

    if hop_ips:
        create_map_from_ips(hop_ips)

if __name__ == "__main__":
    main()
