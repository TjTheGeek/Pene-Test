import unittest

from PasswordCracker import crack


class MyTestCase(unittest.TestCase):
    def test_cracker(self):
        hashType = 'md5', 'sha1'
        passwordfile = 'passwords.txt'
        hashtodecrypt = 'fc5e038d38a57032085441e7fe7010b0', '6ADFB183A4A2C94A2F92DAB5ADE762A47889A5A1'
        # hello world
        result1 = crack(hashType[0], passwordfile, hashtodecrypt[0])
        result2 = crack(hashType[1], passwordfile, hashtodecrypt[1].lower())
        self.assertEqual(result1, 1)
        self.assertEqual(result2, 2)


if __name__ == '__main__':
    unittest.main()
