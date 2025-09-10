import socket
import struct


def validate_ip(ip: str):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except:
            return False

def resolve_dns(dns_name: str, ipv6=False):
    try:
        if ipv6:
            address_info = socket.getaddrinfo(dns_name, None, socket.AF_INET6)
        else:
            address_info = socket.getaddrinfo(dns_name, None, socket.AF_INET)
        return address_info[0][4][0]
    except (socket.error, IndexError):
        return None

def checksum(source_string: str):
    total = 0#
    count_to = (len(source_string) // 2) * 2
    count = 0
    mask = 0xffffffff
    mask_onesix = 0xffff

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        total = total + this_val
        total = total & mask
        count = count + 2

    if count_to < len(source_string):
        total = total + source_string[len(source_string) - 1]
        total = total & mask

    total = (total >> 16) + (total & mask_onesix)
    total = total + (total >> 16)
    answer = ~total
    answer = answer & mask_onesix
    answer = answer >> 8 | (answer << 8 & mask_onesix)
    return answer

def create_icmp_packet(ipv6=False):
    if ipv6:
        icmp_type = 128
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 1
        icmp_seq = 1
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    else:
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 1
        icmp_seq = 1
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        icmp_checksum = checksum(header)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    return header

def get_whois_info(ip):
    iana_server = "whois.iana.org"
    try:
        with socket.create_connection((iana_server, 43), timeout=2) as s:
            s.sendall(f"{ip}\r\n".encode())
            response = s.recv(4096).decode(errors='ignore')

        match = re.search(r"refer:\s*(\S+)", response, re.IGNORECASE)
        if match:
            whois_server = match.group(1).strip()
        else:
            whois_server = iana_server
    except Exception as e:
        print(f"Error whois.iana.org: {e}")
        return None

    try:
        with socket.create_connection((whois_server, 43), timeout=2) as s:
            s.sendall(f"{ip}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        return response.decode()
    except Exception as e:
        print(f"Error {whois_server}: {e}")
        return None

def parse_whois_info(info):
    netname = None
    as_number = None
    country = None
    for line in info.splitlines():
        line = line.strip()
        if line.startswith("netname:"):
            netname = line.split(":")[1].strip()
        elif line.startswith("origin:"):
            as_number = line.split(":")[1].strip()
        elif line.startswith("country:"):
            country = line.split(":")[1].strip().upper()
        elif line.startswith("descr:"):
            if not netname:
                netname = line.split(":")[1].strip()
        elif line.startswith("OrgName:"):
            if not netname:
                netname = line.split(":")[1].strip()
        elif line.startswith("aut-num:"):
            if not as_number:
                as_number = line.split(":")[1].strip()
        elif line.startswith("route:"):
            if not netname:
                netname = line.split(":")[1].strip()
    return netname, as_number, country