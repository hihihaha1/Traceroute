import socket
import time
from Support_functions import create_icmp_packet

def traceroute(destination: str, max_hops=30, timeout=2, ipv6=False, start_ttl=1, ttl_visible=False):
    hop_ips = []

    try:
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, start_ttl)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        for ttl in range(start_ttl, max_hops + 1):
            if ipv6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            packet = create_icmp_packet(ipv6)
            start_time = time.time()
            sock.sendto(packet, (destination, 0))

            try:
                reply, addr = sock.recvfrom(1024)
                ip = addr[0]
                elapsed_ms = (time.time() - start_time) * 1000

                if ip:
                    hop_ips.append(ip)
                    try:
                        host_name = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        host_name = ip

                    if ttl_visible:
                        print(f"TTL: {ttl} - {host_name} ({ip})  {elapsed_ms:.2f} мс\n")
                    else:
                        print(f"{host_name} ({ip})  {elapsed_ms:.2f} мс\n")

                    if ip == destination:
                        print("Трассировка завершена")
                        break
            except socket.timeout:
                print(f"{ttl} *\n")
                hop_ips.append("*")

    except PermissionError:
        print("Ошибка: Недостаточно прав для создания RAW-сокета")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        sock.close()

    return [ip for ip in hop_ips if ip != "*"]