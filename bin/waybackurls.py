import requests
import sys
import json


def waybackurls(host, with_subs):
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    r = requests.get(url)
    results = r.json()
    return results[1:]


if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 2:
        print('Usage:\n\tpython3 waybackurls.py <url> <include_subdomains:optional>')
        sys.exit()

    host = sys.argv[1]
    with_subs = False
    if argc > 3:
        with_subs = True

    urls = waybackurls(host, with_subs)
    json_urls = json.dumps(urls)
    if urls:
        filename = '%s-waybackurls.json' % host
        with open(filename, 'w') as f:
            f.write(json_urls)
        print('[*] Saved results to %s' % filename)
    else:
        print('[-] Found nothing')
