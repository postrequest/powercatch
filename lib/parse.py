# Credits for the parsing go to sqlmap!

import binascii
import re
import six
import base64
import sys

BURP_REQUEST_REGEX = r"={10,}\s+([A-Z]{3,} .+?)\s+={10,}"
BURP_XML_HISTORY_REGEX = r'<port>(\d+)</port>.*?<request base64="true"><!\[CDATA\[([^]]+)'
CRAWL_EXCLUDE_EXTENSIONS = ("3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar", "asf", "au", "avi", "bak", "bin", "bk", "bmp", "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "dat", "deb", "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx")
PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;']+)|(\*/\*)"
UNICODE_ENCODING = "utf8"
NULL = "NULL"

class HTTPMETHOD(object):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"

class HTTP_HEADER(object):
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"

def getUnicode(value, encoding=None, noneToNull=False):
    """
    Returns the unicode representation of the supplied value

    >>> getUnicode('test') == u'test'
    True
    >>> getUnicode(1) == u'1'
    True
    """
    encoding = sys.getfilesystemencoding()

    if noneToNull and value is None:
        return NULL

    if isinstance(value, six.text_type):
        return value
    elif isinstance(value, six.binary_type):
        try:
            return six.text_type(value, encoding, errors="ignore") # assumption made
        except UnicodeDecodeError:
            return six.text_type(value, UNICODE_ENCODING, errors="reversible")
    else:
        try:
            return six.text_type(value)
        except UnicodeDecodeError:
            return six.text_type(str(value), errors="ignore")  # encoding ignored for non-basestring instances

def getText(value, encoding=None):
    """
    Returns textual value of a given value (Note: not necessary Unicode on Python2)

    >>> getText(b"foobar")
    'foobar'
    >>> isinstance(getText(u"fo\\u2299bar"), six.text_type)
    True
    """

    retVal = value

    if isinstance(value, six.binary_type):
        retVal = getUnicode(value, encoding)

    if six.PY2:
        try:
            retVal = str(retVal)
        except:
            pass

    return retVal

def decodeBase64(value, binary=True, encoding=None):
    """
    Returns a decoded representation of provided Base64 value

    >>> decodeBase64("MTIz") == b"123"
    True
    >>> decodeBase64("MTIz", binary=False)
    '123'
    """

    retVal = base64.b64decode(value)

    if not binary:
        retVal = getText(retVal, encoding)

    return retVal

def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])

    >>> filterStringValue('wzydeadbeef0123#', r'[0-9a-f]')
    'deadbeef0123'
    """

    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)

    return retVal

def parseBurpRequest(reqFile):
    """
    Parses Burp logs
    """

    content = open(reqFile).read()
    request = decodeBase64(content, binary=False)

    if not re.search(BURP_REQUEST_REGEX, content, re.I | re.S):
        if re.search(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
            reqResList = []
            for match in re.finditer(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                port, request = match.groups()
                try:
                    request = decodeBase64(request, binary=False)
                except (binascii.Error, TypeError):
                    continue
                _ = re.search(r"%s:.+" % re.escape(HTTP_HEADER.HOST), request)
                if _:
                    host = _.group(0).strip()
                    if not re.search(r":\d+\Z", host):
                        request = request.replace(host, "%s:%d" % (host, int(port)))
                reqResList.append(request)
        else:
            reqResList = [content]
    else:
        reqResList = re.finditer(BURP_REQUEST_REGEX, content, re.I | re.S)

    for match in reqResList:
        request = match if isinstance(match, six.string_types) else match.group(1)
        request = re.sub(r"\A[^\w]+", "", request)
        schemePort = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)

        if schemePort:
            scheme = schemePort.group(1)
            port = schemePort.group(2)
            request = re.sub(r"\n=+\Z", "", request.split(schemePort.group(0))[-1].lstrip())
        else:
            scheme, port = None, None

        if "HTTP/" not in request:
            continue

        if re.search(r"^[\n]*%s.*?\.(%s)\sHTTP\/" % (HTTPMETHOD.GET, "|".join(CRAWL_EXCLUDE_EXTENSIONS)), request, re.I | re.M):
            continue

        getPostReq = False
        url = None
        host = None
        method = None
        data = None
        cookie = None
        params = False
        newline = None
        lines = request.split('\n')
        headers = []

        for index in range(len(lines)):
            line = lines[index]

            if not line.strip() and index == len(lines) - 1:
                break

            newline = "\r\n" if line.endswith('\r') else '\n'
            line = line.strip('\r')
            match = re.search(r"\A([A-Z]+) (.+) HTTP/[\d.]+\Z", line) if not method else None

            if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
                data = ""
                params = True

            elif match:
                method = match.group(1)
                url = match.group(2)

                if any(_ in line for _ in ('?', '=', '*')):
                    params = True

                getPostReq = True

            # POST parameters
            elif data is not None and params:
                data += "%s%s" % (line, newline)

            # GET parameters
            elif "?" in line and "=" in line and ": " not in line:
                params = True

            # Headers
            elif re.search(r"\A\S+:", line):
                key, value = line.split(":", 1)
                value = value.strip().replace("\r", "").replace("\n", "")

                # Note: overriding values with --headers '...'
                #match = re.search(r"(?i)\b(%s): ([^\n]*)" % re.escape(key), conf.headers or "")
                #if match:
                #    key, value = match.groups()

                # Cookie and Host headers
                if key.upper() == HTTP_HEADER.COOKIE.upper():
                    cookie = value
                elif key.upper() == HTTP_HEADER.HOST.upper():
                    if '://' in value:
                        scheme, value = value.split('://')[:2]
                    splitValue = value.split(":")
                    host = splitValue[0]

                    if len(splitValue) > 1:
                        port = filterStringValue(splitValue[1], "[0-9]")

                # Avoid to add a static content length header to
                # headers and consider the following lines as
                # POSTed data
                if key.upper() == HTTP_HEADER.CONTENT_LENGTH.upper():
                    params = True

                # Avoid proxy and connection type related headers
                elif key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION):
                    headers.append((getUnicode(key), getUnicode(value)))

                if '*' in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or ""):
                    params = True

        data = data.rstrip("\r\n") if data else data

        if getPostReq and (params or cookie):
            if not port and hasattr(scheme, "lower") and scheme.lower() == "https":
                port = "443"
            elif not scheme and port == "443":
                scheme = "https"

            if not host:
                errMsg = "invalid format of a request file"
                raise Exception(errMsg)

            if not url.startswith("http"):
                url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
                #scheme = None
                #port = None
    return {'method': method,
            'url': url,
            'host': host,
            'request': content,
            'requestDecoded': request,
            'schemePort': schemePort,
            'port': port,
            'scheme': scheme,
            }