import unittest
from arpSpoofer import get_mac_address


class MyTestCase(unittest.TestCase):
    def test_macaddress(self):
        target = '192.168.1.8'
        result = get_mac_address(target)
        self.assertEqual(result, '00:1c:42:ec:c1:0c')
        print(result)

if __name__ == '__main__':
    unittest.main()
