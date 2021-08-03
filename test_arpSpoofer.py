import unittest
import arpspoofer2


class MyTestCase(unittest.TestCase):
    def test_macaddress(self):
        target = '192.168.1.1'
        result = arpspoofer2.getMacAddress(target)
        print(result)




if __name__ == '__main__':
    unittest.main()
