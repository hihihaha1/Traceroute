import unittest
import unittest.mock as mock
import socket
from io import StringIO
import sys
from Traceroute import tracert


class TestTracerouteFunctions(unittest.TestCase):
    #Тесты корректности адресов
    def test_validate_ip_ipv4_valid(self):
        self.assertTrue(tracert.validate_ip("8.8.8.8"))

    def test_validate_ip_ipv4_invalid(self):
        self.assertFalse(tracert.validate_ip("256.256.256.256"))

    def test_validate_ip_ipv6_valid(self):
        self.assertTrue(tracert.validate_ip("2001:4860:4860::8888"))

    def test_validate_ip_ipv6_invalid(self):
        self.assertFalse(tracert.validate_ip("2001:4860:4860::zzzz"))

    #Тесты разрешения DNS-имен
    @mock.patch('socket.getaddrinfo')
    def test_resolve_dns_ipv4_success(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ('8.8.8.8',))]
        result = tracert.resolve_dns("example.com")
        self.assertEqual(result, "8.8.8.8")

    @mock.patch('socket.getaddrinfo')
    def test_resolve_dns_ipv6_success(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ('2001:4860:4860::8888', 0, 0))]
        result = tracert.resolve_dns("example.com", ipv6=True)
        self.assertEqual(result, "2001:4860:4860::8888")

    @mock.patch('socket.getaddrinfo')
    def test_resolve_dns_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.error
        result = tracert.resolve_dns("nonexistent.example.com")
        self.assertIsNone(result)

    #Проверяет корректность расчёта контрольной суммы для ICMP-пакета
    def test_checksum(self):
        test_string = b'\x08\x00\x00\x00\x00\x01\x00\x01'
        result = tracert.checksum(test_string)
        self.assertEqual(result, 63485)

    #Проверяет создание ICMP-пакета для IPv4
    def test_create_icmp_packet_ipv4(self):
        packet = tracert.create_icmp_packet(ipv6=False)
        self.assertEqual(len(packet), 8)
        self.assertEqual(packet[0], 8)

    #Проверяет создание ICMP-пакета для IPv6
    def test_create_icmp_packet_ipv6(self):
        packet = tracert.create_icmp_packet(ipv6=True)
        self.assertEqual(len(packet), 8)
        self.assertEqual(packet[0], 128)

    #Проверяет успешную трассировку IPv4
    @mock.patch('socket.socket')
    def test_traceroute_ipv4_success(self, mock_socket):
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.recvfrom.side_effect = [
            (b'dummy', ('192.168.1.1', 0)),
            (b'dummy', ('10.0.0.1', 0)),
            (b'dummy', ('8.8.8.8', 0)),
        ]

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out

            tracert.traceroute("8.8.8.8", max_hops=3, ipv6=False)

            output = out.getvalue()
            self.assertIn("192.168.1.1", output)
            self.assertIn("10.0.0.1", output)
            self.assertIn("8.8.8.8", output)
        finally:
            sys.stdout = saved_stdout

    #Проверяет вывод имён хостов
    @mock.patch('socket.socket')
    def test_traceroute_with_hostnames(self, mock_socket):
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.recvfrom.side_effect = [
            (b'dummy', ('192.168.1.1', 0)),
            (b'dummy', ('8.8.8.8', 0)),
        ]

        with mock.patch('socket.gethostbyaddr') as mock_gethost:
            mock_gethost.side_effect = [
                ('router.local', [], []),
                ('dns.google', [], []),
            ]

            saved_stdout = sys.stdout
            try:
                out = StringIO()
                sys.stdout = out

                tracert.traceroute("8.8.8.8", max_hops=2, ipv6=False)

                output = out.getvalue()
                self.assertIn("router.local", output)
                self.assertIn("dns.google", output)
            finally:
                sys.stdout = saved_stdout

    #Проверяет обработку ситуации, когда домен не может быть разрешён
    @mock.patch('tracert.validate_ip')
    @mock.patch('tracert.resolve_dns')
    def test_main_invalid_dns(self, mock_resolve, mock_validate):
        mock_validate.return_value = False
        mock_resolve.return_value = None

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out

            with mock.patch('sys.argv', ['tracert.py', 'invalid.example.com']):
                with self.assertRaises(SystemExit):
                    tracert.main()

            output = out.getvalue()
            self.assertIn("Ошибка: Не удалось разрешить доменное имя", output)
        finally:
            sys.stdout = saved_stdout


if __name__ == "__main__":
    unittest.main()