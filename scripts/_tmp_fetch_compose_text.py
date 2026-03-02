import json
import urllib.parse
import urllib.request
import http.cookiejar

BASE = "http://127.0.0.1:9090"
LOGIN_URL = f"{BASE}/login"
COMPOSE_URL = f"{BASE}/docker/compose_text?scenario=Anatest&name=docker-5&lines=260"


def main() -> int:
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    opener.open(LOGIN_URL, timeout=20).read()
    payload = urllib.parse.urlencode({"username": "coreadmin", "password": "coreadmin"}).encode()
    req = urllib.request.Request(LOGIN_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener.open(req, timeout=20).read()

    raw = opener.open(COMPOSE_URL, timeout=30).read().decode("utf-8", "ignore")
    obj = json.loads(raw)
    print("ok=", obj.get("ok"), "compose=", obj.get("compose"), "exists=", obj.get("exists"))
    head = str(obj.get("head") or "")
    for ln in head.splitlines():
        l = ln.lower()
        if (
            "working_dir" in l
            or "image:" in l
            or "coretg.wrapper_base_image" in l
            or "command:" in l
            or "entrypoint:" in l
        ):
            print(ln)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
