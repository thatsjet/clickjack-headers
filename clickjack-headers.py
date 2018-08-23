# Adapted from Clickjacking_Tester.py by D4vinci

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen
from sys import argv, exit

__author__ = 'thatsjet'

def getHeaders(url):
    try:
        if "http" not in url: url = "https://" + url
        data = urlopen(url)
        headers = data.info()
        return headers
    except: return None

def checkXFrame(headers):
    ''' check given URL contains X-Frame-Options '''
    if "X-Frame-Options" in headers: return True
    else: return False

def checkCSP(headers):
    ''' check given URL contains CSP frame-ancestors options '''
    if "Content-Security-Policy" in headers:
        if "frame-ancestors" in headers['Content-Security-Policy']: return True
    else: return False

def main():
    try: sites = open(argv[1], 'r').readlines()
    except: print("[*] Usage: python(3) clickjack_test.py <file_name>"); exit(0)

    for site in sites[0:]:
        headers = getHeaders(site)

        if not (headers):
            print("\n[*] Couldn't reach: " + site)
            continue

        print("\n[*] Checking " + site.rstrip())

        xf = checkXFrame(headers)
        csp = checkCSP(headers)

        if not (xf|csp):
            print(" [+] ClickJack headers not present. Website is vulnerable!")

        elif (xf|csp):
            if (xf):
                print("\t[+] Found: X-Frame-Options")
            if (csp):
                print("\t[+] Found: CSP frame-ancestors")
        else: print('Something went wrong. Please check your input file and try again.')

if __name__ == '__main__': main()
