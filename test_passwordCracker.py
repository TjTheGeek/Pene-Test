import unittest

from PasswordCracker import crack


class MyTestCase(unittest.TestCase):
    def test_cracker(self):

        passwordfile = '../passwords.txt'
        hashtodecrypt = 'fc5e038d38a57032085441e7fe7010b0', \
                        '6ADFB183A4A2C94A2F92DAB5ADE762A47889A5A1'
        # hello world
        result1 = crack('md5', passwordfile, hashtodecrypt[0])
        result2 = crack('sha1', passwordfile, hashtodecrypt[1].lower())
        self.assertEqual(result1[1], True)
        self.assertEqual(result2[1], True)


if __name__ == '__main__':
    unittest.main()
