# CHunt (Comment Hunter)
```
 _____  _   _             _   
/  __ \| | | |           | |  
| /  \/| |_| |_   _ _ __ | |_ 
| |    |  _  | | | | '_ \| __|
| \__/\| | | | |_| | | | | |_ 
 \____/\_| |_/\__,_|_| |_|\__|

```

CHunt is a powerful Python tool designed to uncover forgotten comments in web applications. It serves as a valuable aid for both developers and penetration testers in gaining insights into the codebase and find **senstive** comments like tokens or passwords.

# QuickStart

```
python3 -m venv .venv # if you want to execute in virtual env
source .venv/bin/activate # if you want to execute in virtual env
pip install -r requirements.txt
python3 chunt.py -t example.com -r -d 3 
```
## Default search words

```
- flag
- root
- admin
- token
- pw
- password
- passwort
- key
- passphrase
- secret
- code
- bearer
- passwd
- credential
```

If you want to add your own words use the `-s` option. If you need to remove default search words use the `-rm` option. To list all used search words, use the option `--show-search-words`.

`python3 chunt.py -t example.com -r -d 3 -rm token -s "foobar"`

## Example
![image](https://github.com/olizimmermann/CHunt/assets/73298827/2ce61114-a157-4fd2-8061-a84c82e45462)


## Usage

```
usage: chunt [-h] [-t TARGET] [-s [SEARCH_WORD ...]] [--wordlist WORDLIST] [-rm [REMOVE_SEARCH_WORD ...]] [-rmds] [--show-search-words] [-d DEPTH] [--show-urls]
             [--show-all-comments] [--disable-js] [--ssl] [-r] [--timeout TIMEOUT] [-H HEADER [HEADER ...]] [--user-agent USER_AGENT] [--referrer REFERRER]
             [-c [COOKIE ...]] [--proxy-host PROXY_HOST] [--proxy-port PROXY_PORT] [--proxy-user PROXY_USER] [--proxy-password PROXY_PASSWORD] [-a {basic,digest}]
             [-u USER] [-p PASSWORD] [--sleep SLEEP] [-v]
             
Spider through your targeted domain and fetch all comments developer left. Especially sensitive ones. Those are defined by search words. CHunt already brings the basic ones but keeps it open to you in the end.

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL/domain
  -s [SEARCH_WORD ...], --search-word [SEARCH_WORD ...]
                        Add own search word[s]
  --wordlist WORDLIST   Wordlist with search words
  -rm [REMOVE_SEARCH_WORD ...], --remove-search-word [REMOVE_SEARCH_WORD ...]
                        Remove a default search word
  -rmds, --remove-default-search-words
                        Remove all default search words
  --show-search-words   Prints out used search words (default: False)
  -d DEPTH, --depth DEPTH
                        Max spider depth (default 1)
  --show-urls           Show overview of all crawled urls (default False)
  --show-all-comments   Show overview of all crawled comments (default False)
  --disable-js          Disable JavaScript comment parsing (BETA) (default False)
  --ssl                 Verify SSL (default False)
  -r, --redirect        Follow redirects (default: False)
  --timeout TIMEOUT     Timeout in seconds for HTTP requests (default 10s)
  -H HEADER [HEADER ...], --header HEADER [HEADER ...]
                        Header infos, usage: -H "Accept:*/*" -H "Accept-Encoding:gzip, deflate"
  --user-agent USER_AGENT
                        Define own user-agent
  --referrer REFERRER   Define referrer
  -c [COOKIE ...], --cookie [COOKIE ...]
                        Add own cookie[s], name=value; name2=value2
  --proxy-host PROXY_HOST
                        Proxy address/host
  --proxy-port PROXY_PORT
                        Proxy port (default 8080)
  --proxy-user PROXY_USER
                        Proxy username
  --proxy-password PROXY_PASSWORD
                        Proxy password
  -a {basic,digest}, --auth {basic,digest}
                        Authentication method [digest, basic]
  -u USER, --user USER  Authentication user
  -p PASSWORD, --password PASSWORD
                        Authentication password
  --sleep SLEEP         Sleep between crawling new found urls (default 0)
  -v, --version         Version of CHunt

CHunt only spiders within the same domain.
```

CHunt is a versatile tool that spiders through your targeted domain, fetching all comments left by developers. It especially focuses on sensitive comments defined by search words. While CHunt already includes basic search words, you have the flexibility to add your own. The tool provides various options for customization, including the ability to show search words, specify spider depth, enable JavaScript comment parsing, and more.

Note that CHunt operates within the same domain and provides options for SSL verification, following redirects, setting timeouts for HTTP requests, customizing headers and user agents, managing cookies, and utilizing proxy settings. It also supports authentication methods such as basic and digest, allowing you to provide credentials if needed.

By running CHunt, you can gather valuable insights from comments left by developers, helping you understand the codebase better, identify potential vulnerabilities, and enhance the overall security of your web application.

For more information about CHunt and its version, refer to the help message provided above.

Don't let valuable comments remain hidden. Uncover them with CHunt (Comment Hunter) and make the most out of your codebase analysis and penetration testing efforts.
