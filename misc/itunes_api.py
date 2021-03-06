"""Wrappers around the iTunes API. Can be used to cache results internally,
wait internally as long as necessary to avoid getting banned by Apple."""

import sqlite3
import requests
import time
import json
import os

STORE_CODE = 'de'
BASE_URL   = 'https://itunes.apple.com/'+STORE_CODE+'/lookup?'

# Schema for table 'cache':
# CREATE TABLE cache (valid_until INTEGER, response TEXT);
cache_db = sqlite3.connect(os.path.join(
        os.path.dirname(__file__),
        "api_cache.db")
)
cache_db.text_factory = str

t_last_request = None


def _cache_api_response(resp, duration):
    """Cache a iTunes API response.

    :param resp The response to cache
    :param duration The time period in seconds for which to cache the data"""
    current_time = int(time.time())
    valid_until  = current_time + duration

    encoded_resp = json.dumps(resp)

    c = cache_db.cursor()
    c.execute('INSERT INTO cache VALUES (?, ?)', (valid_until, encoded_resp, ))
    cache_db.commit()


def _delete_expired_responses():
    current_time = int(time.time())

    c = cache_db.cursor()
    c.execute('DELETE FROM cache WHERE valid_until < ?', (current_time, ))
    cache_db.commit()


def _get_cached_api_response(**kwargs):
    """
    Lookup a response in the cache.

    :param kwargs Matching values. This dictionary is used to find a match to the query.
    :returns The json response, if one was found, else None
    """
    _delete_expired_responses()

    current_time = int(time.time())

    c = cache_db.cursor()
    c.execute('SELECT response FROM cache WHERE valid_until > ?', (current_time, ))
    results = c.fetchall()
    if results:
        for result in results:
            resp = json.loads(result[0])
            if resp is None:
                continue

            args = kwargs.keys()

            # If not every key is in the cached response object
            if not all(map(lambda k: k in resp, args)):
                continue

            # If not all keys are equal between the two dictionaries.
            if not all(map(lambda k: kwargs[k] == resp[k], args)):
                continue

            return resp

    return None


def _construct_url(param_str):
    return BASE_URL + param_str


def send_request(request_url):
    """
    Send a iTunes API request. The function makes sure not to send too many
    requests, in order to avoid getting banned by Apple.

    :param request_url: The iTunes API request URL.
    :return: Decoded JSON response object.
    """
    # Make sure we don't send too many requests.
    global t_last_request

    try:
        current_time = int(time.time())
        if t_last_request is not None and current_time - t_last_request < 5:
            time.sleep(5 - (current_time - t_last_request))
        t_last_request = int(time.time())

        response = requests.get(request_url)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'))
    except:
        return None


def _lookup_in_cache(**kwargs):
    """
    Lookup a iTunes API response in the cache.

    :param kwargs: Keyword argument. We expect either the key bundleId or the key
    trackId (or both)
    :return: Cached API response or None, if no cached response exists.
    """
    if kwargs.get('no-cached', False):
        return None

    if kwargs.get('bundleId', None) is None and kwargs.get('trackId', None) is None:
        return None

    return _get_cached_api_response(**kwargs)


def lookup_metadata(**kwargs):
    """
    Lookup iTunes metadata.

    :param kwargs: Argument dictionary. An example key to use is ``trackId''
           By specifying the ``cache'' parameter, the result is cached for up to
           two hours internally.
    :return: Result dictionary or None, if the lookup failed
    """
    if not kwargs.get('bundleId', False) and not kwargs.get('trackId', False):
        raise ValueError('Invalid usage of lookup metadata function.')

    cached_response = _lookup_in_cache(**kwargs)
    if cached_response:
        return cached_response

    if 'bundleId' in kwargs:
        parameter_str = 'bundleId={}'.format(kwargs['bundleId'])
    else:
        parameter_str = 'id={}'.format(kwargs['trackId'])

    request_url = _construct_url(parameter_str)
    result = None
    response = send_request(request_url)
    if response:
        if response["resultCount"] >= 1:
            result = response['results'][0]

        if kwargs.get('cache', False):
            # By default, cache responses for two hour.
            _cache_api_response(result, 2 * 3600)

    return result
