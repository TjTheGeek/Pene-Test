import unittest

import portScanner


class ScanPortTest(unittest.TestCase):
    def test_if_It_Scans(self):
        # test if the socket connects to an open port
        # using both Ip address or domain name
        port = 80
        timeout = 5
        result = portScanner.scan_port('192.168.1.1', port, timeout)
        result2 = portScanner.scan_port("facebook.com", port, timeout)
        self.assertNotEqual(result, 3)
        self.assertNotEqual(result2, 3)

    def test_checkIP(self):
        # if its an ip address it returns the ipaddress
        ipaddress = '74.125.193.136'
        result = portScanner.check_ip(ipaddress)
        self.assertEqual(result[0], '74.125.193.136')

    def test_checkIpConversion(self):
        ipaddress = 'youtube.com'  # youtube.com ipaddress
        result = portScanner.check_ip(ipaddress)
        self.assertEqual(result[1], True)
        print("Converted IP:" + str(result))

    def test_checkIpConversionError(self):
        ipaddress = 'not a a domain '  # youtube.com ipaddress
        result = portScanner.check_ip(ipaddress)
        self.assertEqual(result[1], False)


if __name__ == '__main__':
    unittest.main()
