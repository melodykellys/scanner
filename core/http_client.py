from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0 Safari/537.36"
)
DEFAULT_TIMEOUT = (5, 12)


def create_session() -> Session:
    retry_policy = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
        raise_on_status=False,
    )
    session = Session()
    session.headers.update({
        "User-Agent": BROWSER_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Connection": "keep-alive",
    })
    adapter = HTTPAdapter(max_retries=retry_policy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
