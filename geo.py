from urllib.request import urlopen
from json import load
import sys
import socket
import validators


def good_netloc(netloc):
    try:
        socket.gethostbyname(netloc)
        return True
    except:
        return False


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def ipInfo(addr): 
    if addr == '':
        url = 'https://ipinfo.io/json'
    else:
        url = 'https://ipinfo.io/' + addr + '/json'
    res = urlopen(url)
    #response from url(if res==None then check connection)
    data = load(res)
    #will load the json response into data
    for attr in data.keys():
        #will print the data line by line
        print(attr,' '*13+'\t->\t',data[attr])


try:
    addr = sys.argv[1].strip()

    if addr.startswith('http://'):
        addr = addr.replace('http://','')
    elif addr.startswith('https://'):
        addr = addr.replace('https://','')
    else:
        pass
    
    if addr.endswith('/'):
        addr = addr[:-1]
    else:
        pass
    
    if validators.domain(addr):
        if good_netloc(addr):
            print('Domain name detected :', addr)
            addr = socket.gethostbyname(addr)
            print ('Converted to IP Address :', addr)
            ipInfo(addr)
            sys.exit()
        else:
            print('Invalid domain name')
            sys.exit()
    elif is_valid_ipv4_address(addr):
        print('Valid IPv4')
        ipInfo(addr)
        sys.exit()
    elif is_valid_ipv6_address(addr):
        print('Valid IPv6')
        ipInfo(addr)
        sys.exit()
    else:
        print('Invalid address')
        sys.exit()

except IndexError as error:
    print('\nYour current location:\n')
    addr = ''
    ipInfo(addr)
    print("""
Usage: geo.py address
    """)
