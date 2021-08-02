import unittest

import portScanner
from PasswordCracker import crack
from arpspoofer2 import getMacAddress


class ScanPortTest(unittest.TestCase):
    def test_checkIpConversion(self):
        ipaddress = 'localhost'
        result = portScanner.checkIP(ipaddress)
        self.assertEqual(result[1], True)
        print("Converted IP:" + str(result))

    def test_if_banner_received(self):
        port = 22
        timeout = 5
        result = portScanner.scanPort('localhost', port, timeout)[2]
        self.assertEqual(result, True)

    def test_checkIpConversionError(self):  # conversion failure
        ipaddress = 'not a a domain '
        result = portScanner.checkIP(ipaddress)
        self.assertEqual(result[1], False)

    def test_cracker(self):
        passwordfile = 'passwords.txt'
        hashtodecrypt = 'fc5e038d38a57032085441e7fe7010b0', \
                        '6ADFB183A4A2C94A2F92DAB5ADE762A47889A5A1', \
                        '936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af'

        # hello world
        result1 = crack('md5', passwordfile, hashtodecrypt[0])
        result2 = crack('sha1', passwordfile, hashtodecrypt[1].lower())
        result3 = crack('sha256', passwordfile, hashtodecrypt[2].lower())
        self.assertEqual(result1[1], True)
        self.assertEqual(result2[1], True)
        self.assertEqual(result3[1], True)

    def test_macaddress(self):  # retrieval of Mac address
        target = '192.168.1.5'
        result = getMacAddress(target)
        self.assertEqual(result, '88:e9:fe:68:53:0a')
        print(result)


if __name__ == '__main__':
    unittest.main()
