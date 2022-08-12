# クエリパラメータ一覧
# d    : [delay] 遅延時間のミリ秒、１回のみ指定可能、複数回指定時は最後のものが有効
# dmax : [delay at maximum] 遅延時間の上限ミリ秒、１回のみ指定可能、複数回指定時は最後のものが有効、dの遅延時間に加算される
# dmin : [delay at minimum] 遅延時間の加減ミリ秒、１回のみ指定可能、複数回指定時は最後のものが有効、dの遅延時間位加算される
# s    : [status] ステータスコード、１回のみ指定可能、複数回指定時は最後のものが有効となる
# r    : [random status] ステータスコードをランダムに返す際は"true"を設定。ステータスコードの割合は次の通り 200-80%, 301-3%, 403-3%, 404-5%, 500-6%, 503-3%
# u    : [upstream] リクエスト送信先のUpstream URL
#
# 備考
# 遅延時間 = d + random( dmin, max(dmin, dmax) )
#
# 環境変数
# PYMOC_SERVER_UPSTREAM : UpstreamサーバのURL。"u"のクエリパラメータと同じ。
# PYMOC_SERVER_HOST     : サーバが待ち受けるホスト名。デフォルトは"0.0.0.0"
# PYMOC_SERVER_PORT     : サーバが受け付けるポート番号。デフォルトは8000。

import os
from time import sleep
import random
import base64
import json
from urllib.request import urlopen
from urllib.parse import urlparse,parse_qs
from urllib.error import URLError,HTTPError
from http.server import HTTPServer,BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import ctypes

PYMOC_SERVER_UPSTREAM=None
if os.environ.get("PYMOC_SERVER_UPSTREAM"):
    PYMOC_SERVER_UPSTREAM=os.environ.get("PYMOC_SERVER_UPSTREAM")
    print("Upstream server set as :", PYMOC_SERVER_UPSTREAM, flush=True)

PYMOC_SERVER_HOST="0.0.0.0"
if os.environ.get("PYMOC_SERVER_HOST"):
    PYMOC_SERVER_HOST=os.environ.get("PYMOC_SERVER_HOST")
    print("Hostname set as :", PYMOC_SERVER_HOST, flush=True)

PYMOC_SERVER_PORT=8000
if os.environ.get("PYMOC_SERVER_PORT"):
    PYMOC_SERVER_PORT=int(os.environ.get("PYMOC_SERVER_PORT"))
    print("Port set as :", PYMOC_SERVER_PORT, flush=True)

PYMOC_OAUTH2PROXY_COOKIE_SECRET=b""
if os.environ.get("PYMOC_OAUTH2PROXY_COOKIE_SECRET"):
    PYMOC_OAUTH2PROXY_COOKIE_SECRET=os.environ.get("PYMOC_OAUTH2PROXY_COOKIE_SECRET").encode(encoding='utf-8')
    print("Cookie secret set as :", PYMOC_OAUTH2PROXY_COOKIE_SECRET, flush=True)

PYMOC_OAUTH2PROXY_COOKIE_NAME="_oauth2_proxy"
if os.environ.get("PYMOC_OAUTH2PROXY_COOKIE_NAME"):
    PYMOC_OAUTH2PROXY_COOKIE_NAME=os.environ.get("PYMOC_OAUTH2PROXY_COOKIE_NAME")
    print("Cookie name set as :", PYMOC_OAUTH2PROXY_COOKIE_NAME, flush=True)

decode_state = None
try:
    decode_state = ctypes.cdll.LoadLibrary("/opt/decodess.so").decode_state
    decode_state.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    decode_state.restype=ctypes.c_char_p
    secret = PYMOC_OAUTH2PROXY_COOKIE_SECRET
except:
    print("Failed to load decodess.so", flush=True)

class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = None

    # @profile
    def do_GET(self):
        o = urlparse(self.path)
        query=parse_qs(o.query)
        headers=self.headers

        self.request_upstream(query.get("u"))
        self.delay(query.get("d"), query.get("dmax"), query.get("dmin"))
        self.status(query.get("s"), query.get("r"))

        # self.request_upstream(header.get_all("u"))
        # self.delay(header.get_all("d"), header.get_all("dmax"), header.get_all("dmin"))
        # self.status(header.get_all("s"), header.get_all("r"))

        body  = ""
        body += self.info_to_str()
        body += self.headers_to_str(headers)
        body += self.jwt_to_str(headers.get("X-Forwarded-Access-Token"))
        body += self.session_state_to_str(headers.get("Cookie"))
        self.send_header('Content-length', len(body.encode()))
        self.send_header('Content-Type', "text/plain; charset=UTF-8")
        self.end_headers()
        self.wfile.write(body.encode())

    # @profile
    def do_POST(self):
        o = urlparse(self.path)
        query=parse_qs(o.query)

        self.request_upstream(query.get("u"))
        self.delay(query.get("d"), query.get("dmax"), query.get("dmin"))
        self.status(query.get("s"), query.get("r"))
        headers=self.headers

        # self.request_upstream(header.get_all("u"))
        # self.delay(header.get_all("d"), header.get_all("dmax"), header.get_all("dmin"))
        # self.status(header.get_all("s"), header.get_all("r"))

        body  = ""
        body += self.info_to_str()
        body += self.headers_to_str(headers)
        body += self.jwt_to_str(headers.get("X-Forwarded-Access-Token"))
        body += self.session_state_to_str(headers.get("Cookie"))
        self.send_header('Content-length', len(body.encode()))
        self.send_header('Content-Type', "text/plain; charset=UTF-8")
        self.end_headers()
        self.wfile.write(body.encode())

    # @profile
    def request_upstream(self, u):
        if u == None and PYMOC_SERVER_UPSTREAM == None:
            return
        upstream = PYMOC_SERVER_UPSTREAM
        if u != None:
            upstream=u[-1]
        try:
            r = urlopen(upstream)
        except HTTPError as e:
            print(e.code, e.reason, flush=True)
        except URLError as e:
            print(e.reason, flush=True)

    # @profile
    def delay(self, d, dmax, dmin):
        if d == None:
            d = [0]
        if dmin == None:
            dmin = [0]
        if dmax == None:
            dmax = [dmin[-1]]
        try:
            delay_ms = int(d[-1]) + random.randint(int(dmin[-1]), int(dmax[-1]))
            if delay_ms > 0:
                sleep(delay_ms/1000)
        except:
            pass

    # @profile
    def status(self, s, r):
        if s != None :
            try:
                self.send_response(int(s[-1]))
                return
            except:
                pass
        if r != None and r[-1] == "true":
            result = random.randint(1, 100)
            if result <= 3:
                self.send_response(301)
            elif result <= 6:
                self.send_response(403)
            elif result <= 11:
                self.send_response(404)
            elif result <= 17:
                self.send_response(500)
            elif result <= 20:
                self.send_response(503)
            else:
                self.send_response(200)
            return
        self.send_response(200)

    # @profile
    def info_to_str(self):
        string = "\n"
        string += "======== Information ========\n"
        string += "■Client Address : " + str(self.client_address) + "\n"
        string += "■Request Line : " + self.requestline + "\n"
        string += "■Server Version : " + self.server_version + "\n"
        string += "■System Version : " + self.sys_version + "\n"
        string += "■Protocol Version : " + self.protocol_version + "\n"
        string += "=============================\n"
        return string

    # @profile
    def headers_to_str(self, header):
        if header == None or len(header) == 0:
            return ""
        string = "\n"
        string += "========== Headers ==========\n"
        for k,v in header.items():
            string += "■" + k + " : " + v +"\n"
        string += "=============================\n"
        return string

    # @profile
    def jwt_to_str(self, jwt):
        if jwt == None or jwt == "":
            return ""
        tmp = jwt.split('.')
        headerb64 = tmp[0]
        payloadb64 = tmp[1]
        if len(headerb64) % 4 != 0:
            headerb64 += '=' * (4 - len(headerb64) % 4)
        if len(payloadb64) % 4 != 0:
            payloadb64 += '=' * (4 - len(payloadb64) % 4)
        header = json.loads(base64.b64decode(headerb64).decode())
        payload = json.loads(base64.b64decode(payloadb64).decode())
        string = "\n"
        string += "======== JWT Content ========\n"
        string += "■Headers\n" + json.dumps(header, indent=2) +"\n"
        string += "■Pyloads\n" + json.dumps(payload, indent=2) +"\n"
        string += "=============================\n"
        return string

    # @profile
    def session_state_to_str(self, cookie):
        if decode_state == None:
            return ""
        if cookie == None or cookie == "":
            return ""
        cookie_header=PYMOC_OAUTH2PROXY_COOKIE_NAME+"="
        if not cookie.startswith(cookie_header):
            return ""
        cookie = cookie.split("|")[0].lstrip(cookie_header)
        encoded = cookie.encode(encoding='utf-8')
        result = decode_state(PYMOC_OAUTH2PROXY_COOKIE_SECRET, encoded)
        string = "\n"
        string += "======= Session State =======\n"
        string += result.decode(encoding='utf-8') +"\n"
        string += "=============================\n"
        return string

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

with ThreadedHTTPServer((PYMOC_SERVER_HOST, PYMOC_SERVER_PORT), handler) as httpd:
    print("Moc server started at {}:{}".format(PYMOC_SERVER_HOST, PYMOC_SERVER_PORT), flush=True)
    httpd.serve_forever()
