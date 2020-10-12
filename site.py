# This script is for detecting ssl schema 
# and every potential vulnerability related to it


import sys
import validators
import socket
import requests


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


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


def scanSite(target):
    try:
        responds = requests.get(target)

        # Redirection
        if responds.history:
            print(R + '[!] Redirections found on the target')
            print(R + '[!] Root page / redirects to :', responds.url)
        else:
            print(G + '[+] No redirections found on the target')

        # Server
        try:
            server_info = responds.headers.get('Server')
            if server_info != None:
                print(R + '[!] Server Information is not configured to be hidden :', server_info)
            else:
                print(G + '[+] Server Information is hidden')
        except:
            print(G + '[+] Could not retrieve Server Information')

        # X-Powered-By
        try:
            powered_by = responds.headers.get('X-Powered-By')
            if powered_by != None:
                print(R + '[!] X-Powered-By is not configured to be hidden :', powered_by)
            else:
                print(G + '[+] X-Powered-By is hidden')
        except:
            print(G + '[+] Could not retrieve X-Powered-By')

        # X-AspNet-Version
        try:
            aspnet_version = responds.headers.get('X-AspNet-Version')
            if aspnet_version != None:
                print(R + '[!] X-AspNet-Version is exposed :', aspnet_version)
            else:
                print(G + '[+] X-AspNet-Version is not detected')
        except:
            print(G + '[+] Could not retrieve X-AspNet-Version')
        
        # X-AspNetMvc-Version
        try:
            aspnetmvc_version = responds.headers.get('X-AspNetMvc-Version')
            if aspnetmvc_version != None:
                print(R + '[!] X-AspNetMvc-Version is exposed :', aspnetmvc_version)
            else:
                print(G + '[+] X-AspNetMvc-Version is not detected')
        except:
            print(G + '[+] Could not retrieve X-AspNetMvc-Version')

        # Insecure communication
        if target.startswith('http://'):
            print(R + '[!] The network communication is not secure')
        elif target.startswith('https://'):
            print(G + '[+] The network communication is secure with SSL')
        else:
            pass

        # Unencrypted password submissions
        if target.startswith('http://'):
            print(R + '[!] Passwords are submitted unencrypted over the network')
        elif target.startswith('https://'):
            print(G + '[+] Data is encrypted over the network')
        else:
            pass

        # Robots.txt
        try:       
            if requests.get(target + '/robots.txt').status_code == 200:
                print(R + '[!] Found /robots.txt file')
            elif requests.get(target + '/robots.txt').status_code == 404:
                print(G + '[+] No /robots.txt file found')
            else:
                pass
        except:
            print(G + '[+] Could not retrieve robot file')    

        # Insecure HTTP cookies
        try:
            cookies_info = responds.headers.get('Set-Cookie')
            if 'Secure' in cookies_info:
                print(G + '[+] Cookies HTTP Secure flag is set')
            else:
                print(R + '[!] Cookies HTTP Secure flag is not set')
            if 'HttpOnly' in cookies_info:
                print(G + '[+] Cookies HTTP HttpOnly flag is set')
            else:
                print(R + '[!] Cookies HTTP HttpOnly flag is not set')
        except:
            print(R + '[!] No Set-Cookie HTTP Header retrieved')
            print(R + '[!] Cookies HTTP Secure flag is not set')
            print(R + '[!] Cookies HTTP HttpOnly flag is not set')

        # Missing HTTP Security X-XSS-Protection Header
        try:
            xss_protection = responds.headers.get('X-XSS-Protection')
            if xss_protection != None:
                print(G + '[+] X-XSS-Protection is set')
            else:
                print(R + '[!] X-XSS-Protection is not available')
        except:
            print(R + '[!] X-XSS-Protection is not available')

        # Missing HTTP Security X-Content-Type-Options Header 
        try:
            content_type_options = responds.headers.get('X-Content-Type-Options')
            if content_type_options != None:
                print(G + '[+] X-Content-Type-Options is set')
            else:
                print(R + '[!] X-Content-Type-Options is not set')
        except:
            print(R + '[!] X-Content-Type-Options is not set')

        # Missing HTTP Security X-Frame-Options Header 
        try:
            frame_options = responds.headers.get('X-Frame-Options')
            if frame_options != None:
                print(G + '[+] The anti-clickjacking X-Frame-Options is available')
            else:
                print(R + '[!] The anti-clickjacking X-Frame-Options is unavailable')
        except:
            print(R + '[!] The anti-clickjacking X-Frame-Options is unretrievable')
        
        # ETags Server leaks
        try:
            etags = responds.headers.get('ETag')
            if '-' in etags :
                print(R + '[!] Etags could be leaking Server inodes')
            else:
                print(G + '[+] Etags secured')
        except:
            print(G + '[+] Etags headers is not set')
        
        # Missing HTTP Security Content-Security-Policy Header
        try:
            content_security_policy = responds.headers.get('Content-Security-Policy')
            if content_security_policy != None:
                print(G + '[+] Content-Security-Policy is set')
            else:
                print(R + '[!] Missing Content-Security-Policy directive')
        except:
            print(R + '[!] Could not retrieve Content-Security-Policy')

    except:
        print(R + '[-] Something is wrong with the url')
    
try:
    target = sys.argv[1].strip()

    if not (target.startswith('http://') or target.startswith('https://')):
        print('The address needs to include schemas')
        sys.exit()
    else:
        pass
    
    addr = target.replace('http://','').replace('https://','')
    if addr.endswith('/'):
        addr = addr[:-1]
    else:
        pass

    if validators.domain(addr):
        if good_netloc(addr):
            print('Domain name detected :', addr)
            addr = socket.gethostbyname(addr)
            print ('Converted to IP Address :', addr)
            scanSite(target)
            sys.exit()
        else:
            print('Bad netloc')
            sys.exit()
    elif is_valid_ipv4_address(addr):
        print('Valid IPv4')
        scanSite(target)
        sys.exit()
    elif is_valid_ipv6_address(addr):
        print('Valid IPv6')
        scanSite(target)
        sys.exit()
    else:
        print('Invalid address')
        sys.exit()

except IndexError as error:
    print("""
Usage: site.py address
    """)
