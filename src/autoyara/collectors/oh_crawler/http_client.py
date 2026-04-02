import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

H = {"User-Agent": "Mozilla/5.0"}
SESSION = requests.Session()
SESSION.headers.update(H)


def get(url, allow_html=False):
    try:
        r = SESSION.get(url, timeout=20, verify=False)
        r.raise_for_status()
        t = r.content.decode("utf-8", errors="replace")
        if not allow_html and ("<html" in t[:300] or t.lstrip().startswith("<!")):
            return None
        return t
    except requests.RequestException as e:
        print("  [err] " + str(e)[:80])
        return None
