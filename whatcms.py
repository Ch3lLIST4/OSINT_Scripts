import sys
import requests
import json


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


try:
    print ('\n\n' + Y + '[!]' + ' Malware Scanner :' + W + '\n')

    target = sys.argv[1]
    cms_key = None
    
    if cms_key == None:
        print(R + '[-]' + C + ' Please provide a key\n' + W + '\n')
        sys.exit()
    else:
        response = requests.get('https://whatcms.org/API/CMS?key=' + cms_key + '&url=' + target)
        json_data = json.loads(response.text)

        cms_detected = None
        for k,v in json_data.items():
            if k != 'result':
                print(G + '[+] ' + C + str(k).capitalize() + ' : ' + W + str(v))
            elif k == 'result':
                print(G + '[+] ' +  C + str(k).capitalize() + ' :' + W)
                for key, value in v.items():
                    print('      |--  ' + C + str(key) + ' : ' + R + str(value) + W)
                    if key == 'name' and value != None:
                        cms_detected = value
            else:
                pass

        print()
        if cms_detected != None:
            print(R + '[!]' + C + ' CMS detected on site : ' + R + str(cms_detected) + '\n\n' + W)
        else:
            print(G + '[+]' + C + ' No Content Management System detected on site\n\n' + W)    

except IndexError as e:
    print("""usage : python3 whatcms.py addr

    """)
    pass
except Exception as e:
    print(str(e))