"""
This module creates and maintains HTTP request ecosystem.
It now uses requests for easy compatibility acroos python versions
"""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from contextlib import contextmanager
import logging
import time

import requests
import requests.packages.urllib3
from requests_toolbelt.auth.http_proxy_digest import HTTPProxyDigestAuth

from vms import logger_name


requests.packages.urllib3.disable_warnings()
LOG_NAME = logger_name + ".request"
LOG = logging.getLogger(LOG_NAME)
_REQUEST_ATTRS = {"verify": False, "auth": None, "proxies": {}}


def init(settings):
    """
    Initialize important settings related to request framework
    :param settings: A dict with following keys:
                       - insecure. Boolean. Should HTTPS verification be off
                       - use_socks. Boolean. Use a socks proxy
                       - username. String. Proxy auth username.
                                   If not given, no auth is setup
                       - password. String. Proxy auth pass.
                       - proxy_server. String. Full name of the proxy server
                                       Including port
                       - proxy_auth. String. One of "basic" or "digest"
    """
    # Insecure setting
    insecure = settings.get("insecure", False)
    # Check if proxy is required
    pr = settings.get("proxy_server", "")
    proxies = {}
    auth = None
    global _REQUEST_ATTRS
    _REQUEST_ATTRS["init"] = True
    if not pr:
        # No proxy and no auth
        pass
    else:
        user = settings.get("username", "")
        pass_ = settings.get("password", "")
        if not user:
            noauth = True
        else:
            noauth = False
        use_socks = settings.get("use_socks", False)
        proxy_auth = settings.get("proxy_auth", "basic")
        # Build the auth string first
        pr_str = ""
        set_digest_auth = False
        if not noauth:
            if proxy_auth == "basic" or use_socks:
                pr_str = "{0}:{1}@{2}".format(user, pass_, pr)
            else:
                set_digest_auth = True
        if not pr_str:
            pr_str = "{0}".format(pr)
        if use_socks:
            pr_str = "socks5h://{0}".format(pr_str)
            proxies = {"http": pr_str, "https": pr_str}
        else:
            proxies = {"http": "http://{0}".format(pr_str),
                       "https": "https://{0}".format(pr_str)}
        if set_digest_auth:
            auth = HTTPProxyDigestAuth(user, pass_)
    _REQUEST_ATTRS["verify"] = not insecure
    _REQUEST_ATTRS["auth"] = auth
    _REQUEST_ATTRS["proxies"] = proxies


def _get_request_obj():
    global _REQUEST_ATTRS
    r = requests.Session()
    if _REQUEST_ATTRS["auth"] is not None:
        r.auth = _REQUEST_ATTRS["auth"]
    if _REQUEST_ATTRS["proxies"]:
        r.proxies = _REQUEST_ATTRS["proxies"]
    r.verify = _REQUEST_ATTRS["verify"]
    return r


@contextmanager
def get_request_obj():
    try:
        s = _get_request_obj()
        yield s
    finally:
        s.close()


def _open_url(req_ses, url, timeout=5):
    """
    Open a URL and return response

    :param req_ses: A Requests.session object
    :param url: - The URL to open
    :param timeout: The timeout interval in seconds Defaults to 2.

    Returs repsonse of the website as unicode or raises IOError if
    URL can't be opened
    """
    if "://" not in url:
        url = "http://" + url
    error = None
    try:
        resp = req_ses.get(url, timeout=timeout)
        resp.raise_for_status()
    except requests.Timeout:
        LOG.warning("Request Timed out for URL {0}".format(url))
        error = "Timeout"
    except requests.HTTPError as e:
        error = "{0}".format(e)
    except requests.ConnectionError:
        error = "Connection Failed"
    if error is None:
        return resp.text
    else:
        raise IOError(error)


def open_url(req_ses, url, timeout=5, retries=3):
    """
    Opens a URL and return response.
    This function is a wrapper around the _open_url call

    :param req_ses: A Requests.session object
    :param url: - The URL to open
    :param timeout: The timeout interval in seconds Defaults to 2.
    :param retries: Number of times we should retry a call

    Returs repsonse of the website as unicode or raises IOError if
    URL can't be opened
    """
    count = 1
    err = False
    while True:
        try:
            resp = _open_url(req_ses, url, timeout=timeout)
        except IOError as e:
            msg = "HTTP call failed with error: {0}.".format(e)
            count += 1
            if count <= retries:
                msg = msg + " Will Retry"
            else:
                msg = msg + " Retries exhausted. Giving up"
                err = True
            LOG.debug(msg)
            if err:
                raise
            else:
                time.sleep(0.2)
        else:
            return resp
