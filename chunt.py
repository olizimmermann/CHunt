#!/usr/bin/python3
import argparse
import os
import sys
import re
import signal
import warnings
from time import sleep
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from bs4 import BeautifulSoup as bs
from bs4 import Comment, XMLParsedAsHTMLWarning
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning, module='bs4')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

version = '0.1.1'

banner = """

 _____  _   _             _   
/  __ \| | | |           | |  
| /  \/| |_| |_   _ _ __ | |_ 
| |    |  _  | | | | '_ \| __|
| \__/\| | | | |_| | | | | |_ 
 \____/\_| |_/\__,_|_| |_|\__|
         The Comment Hunter                            
         Github @olizimmermann

"""


print(banner)

class bcolors:
    # print(f"{bcolors.WARNING}Warning: No active frommets remain. Continue?{bcolors.ENDC}")
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def signal_handler(sig, frame):
    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} User aborted')
    sys.exit(1)

def line():
    print('[+]')

def get_wordlist(path: str) -> list:
    wordlist = []
    if not os.path.isfile(path):
        print(f'{bcolors.WARNING}[!]{bcolors.ENDC} Given wordlist not found: {path}')
        return []
    with open(path, 'rt') as f:
        for line in f:
            search_word = line.replace('\n','')
            if search_word not in wordlist and search_word.strip() != "":
                wordlist.append(search_word.strip())
    if len(wordlist) > 0:
        print(f'[+] Wordlist added ({len(wordlist)} search words)')
    else:
        print(f'{bcolors.FAIL}[!]{bcolors.ENDC} Given wordlist contains 0 entries: {path}')
    return wordlist

def prepare_search_words(search_words: list = None, wordlist: list = None, remove_words: list = None, show_search_words: bool = False) -> list:
    final_wordlist = []
    ignore_words = []
    if not args.remove_default_search_words:
        default_words = "flag,root,admin,token,pw,password,passwort,key,passphrase,secret,code,bearer,passwd,credential".split(',')
    else:
        default_words = []
    if remove_words is not None:
        for remove_word in remove_words:
            for rw in remove_word:
                rw = rw.lower()
                ignore_words.append(rw)

    if search_words is not None:
        for search_word in search_words:
            for sw in search_word:
                sw = sw.lower()
                if sw not in default_words and sw not in ignore_words:
                    final_wordlist.append(sw)
    
    if wordlist is not None:
        for search_word in wordlist:
            search_word = search_word.lower()
            if search_word not in default_words and search_word not in ignore_words and search_word not in final_wordlist:
                final_wordlist.append(search_word)

    for search_word in default_words:
        search_word = search_word.lower()
        if search_word not in ignore_words:
            final_wordlist.append(search_word)

    print(f'[+] Used search words: {len(final_wordlist)}')
    if show_search_words:
        line()
        for word in final_wordlist:
            print(f'[+] Search word: {word}')

    return final_wordlist

def prepare_cookies(cookies : list) -> dict:
    final_cookies = {}

    if cookies is None:
        print(f'[i] No cookies used')
        return {}

    for cookie in cookies:
        for cookie_string in cookie:
            for c in cookie_string.split(' '):
                try:
                    key = c.split('=')[0]
                    value = c.split('=')[1]
                    if value.endswith(';'):
                        value = value[:-1]
                    final_cookies[key] = value
                except:
                    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} Could not read cookie {c}')
                    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} Please use --cookie "key=value; key2=value2" or --cookie key=value --cookie key2=value2')
    

    if len(final_cookies) > 0:
        line()
        print('[+] Using Cookies')
        for cookie in final_cookies:
            print(f'[+] Cookie: {cookie} = {final_cookies[cookie]}')
    return final_cookies

def prepare_proxies(proxy_host: str = None, proxy_port: int = None, proxy_user: str = None, proxy_password: str = None) -> dict:
    if proxy_host is None:
        proxies = None
        print('[i] No proxy defined')
    elif proxy_user is None:
        proxy_host = proxy_host.replace('http://', '').replace('https://', '')
        proxies = {'https': f'http://{proxy_host}:{proxy_port}', 'http': f'http://{proxy_host}:{proxy_port}'}
        print(f'[+] Proxy defined: http://{proxy_host}:{args.proxy_port}')
    else:
        proxy_host = proxy_host.replace('http://', '').replace('https://', '')
        proxies = {'https': f'http://{proxy_user}:{proxy_password}@{proxy_host}:{proxy_port}', 'http': f'http://{proxy_user}:{proxy_password}@{proxy_host}:{proxy_port}'}
        print(f'[+] Proxy defined: http://{proxy_user}:{proxy_password}@{proxy_host}:{proxy_port}')
    return proxies

def prepare_target(target) -> tuple:
    if 'http://' not in target and 'https://' not in target:
        if args.ssl:
            target = 'https://' + target
        else:
            target = 'http://' + target
    
    if target.endswith('/'):
        target = target[:-1]

    try:
        domain = urlparse(target).netloc
        print(f'[+] Domain in scope for spidering: {bcolors.BOLD}{domain}{bcolors.ENDC}')
    except:
        print(f'{bcolors.FAIL}[!]{bcolors.ENDC} No valid target given: {target}')
        print('\n\n')
        parser.print_help()
        sys.exit(1)

    return (target, domain)

def prepare_headers(headers, user_agent, referrer) -> dict:
    final_headers = {}
    if headers is not None:
        for header in headers:
            for h in header:
                try:
                    key = h.split(':')[0].strip()
                    value = h.split(':')[1].strip()
                    final_headers[key.title()] = value
                except:
                    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} Wrong format for header used: {h}')
    if user_agent is not None:
        final_headers['User-Agent'] = user_agent
    else:
        final_headers['User-Agent'] = f'CHunt/{version}'
        # use google bot user agent
        # final_headers['User-Agent'] = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    if referrer is not None:
        final_headers['Referer'] = referrer
    
    if len(final_headers) > 0:
        for k in final_headers:
            print(f'[+] Header: {k}: {final_headers[k]}')
    
    return final_headers

def run(args, search_words):
    line()
    session = requests.Session()
    proxies = prepare_proxies(proxy_host=args.proxy_host, proxy_port=args.proxy_port, proxy_user=args.proxy_user, proxy_password=args.proxy_password)
    if proxies is not None: 
        session.proxies.update(proxies)

    if args.user is not None:
        if args.auth == 'basic':
            print('[+] Using basic authentication')
            session.auth = HTTPBasicAuth(args.user, args.password)
        elif args.auth == 'digest':
            print('[+] Using digest authentication')
            session.auth = HTTPDigestAuth(args.user, args.password)

    cookies = prepare_cookies(args.cookie)
    headers = prepare_headers(args.header, args.user_agent, args.referrer)
    target, domain = prepare_target(args.target)

    targets = set()
    targets.add(target)

    oos_targets = set()
    
    scanned = set()

    all_comments = []
    sensitive_comments = []
    
    
    js_comment_pattern = r'[^:]\/\/.*|\/\*[\s\S]*?\*\/'
    print(f'[+] Disable JS comments: {args.disable_js}')

    print(f'[+] Max depth for spidering: {args.depth}')
    try:
        for cur_depth in range(args.depth):
            line()
            if len(targets.difference(scanned)) == 0:
                break
            print(f'[i] Depth {cur_depth+1}')
            for url in targets.difference(scanned):
                try:
                    ret = session.get(url, verify=args.ssl, cookies=cookies, allow_redirects=args.redirect, headers=headers, timeout=args.timeout)
                except Exception as e:
                    if e is KeyboardInterrupt:
                        raise KeyboardInterrupt
                    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} 400 {url}')
                    scanned.add(url)
                    continue
                scanned.add(url)

                if ret.ok:
                    print(f'[+] {ret.status_code} {url}')
                    soup = bs(ret.text, 'html.parser')
                    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                    js = soup.find_all('script')
                    new_urls = soup.find_all('a') + soup.find_all('link')
                    for u in new_urls:
                        href = u.get('href')
                        if href is not None:
                            href = href.strip()
                            href_domain = urlparse(href).netloc
                            if not href.startswith('./') and not href.startswith('/') and not href.startswith('#'):
                                if href_domain is None or href_domain == "":
                                    continue
                        if href is not None and href.startswith('/'):
                            href = urljoin(url, href)
                            href_domain = urlparse(href).netloc
                        if href is not None and href.startswith('./'):
                            href = urljoin(url , href)
                            href_domain = urlparse(href).netloc
                        if href is not None and href.startswith('#'):
                            href = urljoin(url , href)
                            href_domain = urlparse(href).netloc
                        if href is not None and domain == href_domain:
                            if not href.endswith('.pdf') and not href.endswith('.jpg') and not href.endswith('.jpeg') and not href.endswith('.png'):
                                targets.add(href)
                        elif href is not None and href not in targets:
                            oos_targets.add(href)

                            
                        
                    for c in comments:
                        c = c.extract()
                        if c.strip() != "":
                            all_comments.append({'url': url, 'comment': c})
                            for sw in search_words:
                                if sw.lower() in c.lower():
                                    sensitive_comments.append({'url': url, 'comment': c})
                                    break
                    if not args.disable_js:
                        for script in js:
                            script = script.text
                            js_comments = re.findall(js_comment_pattern, script)
                            if js_comments is not None and len(js_comments) > 0:
                                for js_comment in js_comments:
                                    if js_comment != "":
                                        js_comment = js_comment.replace('/*','').replace('*/','').replace('//','').strip()
                                        all_comments.append({'url': url, 'comment': js_comment})
                                        for sw in search_words:
                                            if sw.lower() in js_comment.lower():
                                                sensitive_comments.append({'url': url, 'comment': js_comment})

                else:
                    print(f'{bcolors.FAIL}[!]{bcolors.ENDC} {ret.status_code} {url}')
                if args.sleep is not None:
                    sleep(args.sleep)
    except KeyboardInterrupt:
        print(f'{bcolors.FAIL}[!]{bcolors.ENDC} User aborted')
    signal.signal(signal.SIGINT, signal_handler)
    line()
    print('[+] Result:')
    print(f'[+] {len(scanned)}/{len(targets)} URLs scanned')
    print(f'[i] Out of scope: {len(oos_targets)} URLs')

    if args.show_urls:
        line()
        print('[+] URLs in scope:')
        for u in targets:
            state = 'scanned' if u in scanned else 'not scanned'
            box = '+' if u in scanned else '!'
            print(f'[{box}] {u} ({state})')
        line()
        print('[i] URLs not in scope:')
        for oos in oos_targets:
            if oos is not None or oos.strip() != "":
                print(f'[i] {oos} (not scanned)')


    if len(sensitive_comments) > 0:
        line()
        print(f'[+] {len(sensitive_comments)} findings')
        for sc in sensitive_comments:
            print(f'[+] '+100*'=')
            print('[+] URL: {}'.format(sc['url']))
            print(f'[+] Comment: {bcolors.WARNING}{sc["comment"]}{bcolors.ENDC}')
            line()
    else:
        line()
        print(f'[i] {bcolors.OKGREEN}No sensitive comments found :){bcolors.ENDC}')
    if args.show_all_comments and len(all_comments) > 0:
        line()
        print(f'[+] All comments ({len(all_comments)}):')
        for ac in all_comments:
            print('[+] '+100*'=')
            print('[+] URL: {}'.format(ac['url']))
            print('[+] Comment: {}'.format(ac['comment']))
            line()
    if len(all_comments) > 0:
        print(f'[i] {len(all_comments)} comments found')
        print('[+] '+100*'=')
    line()
    print('[+] Comment Hunt finished')

def main():
    if args.version:
        print(f'[i] CHunt Version {version}')
        sys.exit(1)

    if args.target is None:
        print(f'{bcolors.FAIL}[!]{bcolors.ENDC} Target needs to be defined')
        print('\n\n')
        parser.print_help()
        sys.exit(1)
    
    print('[+] Starting CHunt')
    print('[+]')

    if args.wordlist is not None:
        wordlist = get_wordlist(args.wordlist)
    else:
        wordlist = None
    
    search_words = prepare_search_words(search_words=args.search_word, wordlist=wordlist, remove_words=args.remove_search_word, show_search_words=args.show_search_words)
    
    if len(search_words) == 0:
        print(f'{bcolors.FAIL}[!]{bcolors.ENDC} No search words defined')
        print('\n\n')
        parser.print_help()
        sys.exit(1)
    
    run(args, search_words)



parser = argparse.ArgumentParser(prog='chunt', description="Spider through your targeted domain and fetch all comments developer left. Especially sensitive ones. Those are defined by search words. CHunt already brings the basic ones, but keeps it open to you in the end.", epilog="CHunt only spiders within the same domain.")

parser.add_argument('-t', '--target', type=str, help="Target URL/domain", required=False)
parser.add_argument('-s', '--search-word', type=str, help="Add own search word[s]", required=False, nargs='*', action='append')
parser.add_argument('--wordlist', type=str, help="Wordlist with search words", required=False)
parser.add_argument('-rm', '--remove-search-word',type=str, help="Remove a default search word", required=False, nargs='*', action='append')
parser.add_argument('-rmds','--remove-default-search-words', help="Remove all default search words", required=False, action='store_true')
parser.add_argument('--show-search-words', help="Prints out used search words (default: False)", required=False, action='store_true')

parser.add_argument('-d', '--depth', type=int, help="Max spider depth (default 1)", default=1, required=False)

parser.add_argument('--show-urls', help="Show overview of all crawled urls (default False)", required=False, action='store_true')
parser.add_argument('--show-all-comments', help="Show overview of all crawled comments (default False)", required=False, action='store_true')

parser.add_argument('--disable-js', help="Disable JavaScript comment parsing (BETA) (default False)", required=False, action='store_true')

parser.add_argument('--ssl', help="Verify SSL (default False)", required=False, action='store_true')
parser.add_argument('-r', '--redirect', help="Follow redirects (default: False)", required=False, action='store_true')
parser.add_argument('--timeout', type=int, help="Timeout in seconds for HTTP requests (default 10s)", default=10, required=False)

parser.add_argument('-H', '--header', type=str, help='Header infos, usage: -H "Accept:*/*" -H "Accept-Encoding:gzip, deflate"', required=False, nargs='+', action='append')
parser.add_argument('--user-agent', type=str, help="Define own user-agent", required=False)
parser.add_argument('--referrer', type=str, help="Define referrer", required=False)
parser.add_argument('-c', '--cookie', type=str, help="Add own cookie[s], name=value; name2=value2", required=False, nargs='*', action='append')

parser.add_argument('--proxy-host', type=str, help="Proxy address/host", required=False)
parser.add_argument('--proxy-port', type=int, help="Proxy port (default 8080)", default=8080, required=False)
parser.add_argument('--proxy-user', type=str, help="Proxy username", required=False)
parser.add_argument('--proxy-password', type=str, help="Proxy password", required=False)

parser.add_argument('-a', '--auth', type=str, help="Authentication method [digest, basic]", required=False, choices=['basic', 'digest'])
parser.add_argument('-u', '--user', type=str, help="Authentication user", required=False)
parser.add_argument('-p', '--password', type=str, help="Authentication password", required=False)

parser.add_argument('--sleep', type=int, help="Sleep between crawling new found urls (default 0)", default=0, required=False)
parser.add_argument('-v', '--version', help="Version of CHunt", required=False, action='store_true')

args = parser.parse_args()


if __name__ == '__main__':
    main()
