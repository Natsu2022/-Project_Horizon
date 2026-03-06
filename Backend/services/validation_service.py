from urllib.parse import urlparse


def validate_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https")
    except:
        return False