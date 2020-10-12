import sys
import socket
import requests
import validators
import json


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


# Provie your apikey here
api_key = ''


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


def scanVirusTotal(addr): 
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report?apikey=' + api_key + '&resource=' + addr)
        json_data = json.loads(response.text)
        
        count = 0
        for k,v in json_data.items():
            if k != 'scans':
                print(C + str(k).capitalize() + ' : ' + W + str(v))
            elif k == 'scans':
                print(C + str(k).capitalize() + ' :' + W)
                for engine in v.items():
                    if (engine[1].get('detected') == False):
                        print('  |--  ' + C + engine[0] + ' : ' + G + str(engine[1]) + W)
                    elif(engine[1].get('detected') == True):
                        print('  |--  ' + C + engine[0] + ' : ' + R + str(engine[1]) + W)
                        count = count + 1
            else:
                pass

        if count > 0:
            print('\n' + R + '[!] ' + str(count) + ' total engines confirmed your site is malicious. Your site is malicious, check data for more info\n')
        elif count == 0:
            print('\n' + G + '[+] ' + str(count) + ' total engines detected any malware. Your site looks secure\n')
        else:
            pass
    except Exception as error:
        print(error)
        pass
        

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
            print('\nGood necloc detected : ' +  addr + '\n')
            scanVirusTotal(addr)
            sys.exit()
        else:
            print('Invalid domain name')
            sys.exit()
    elif is_valid_ipv4_address(addr) or is_valid_ipv6_address(addr):
        print('Valid IP Address')
        print('IP Address Types is not supported for this function, please provide a valid domain name')
        sys.exit()
    else:
        print('Invalid address')
        sys.exit()

except IndexError as error:
    print("""
Usage: virus.py address
    """)
except Exception as error:
    print(error)
