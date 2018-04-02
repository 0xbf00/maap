import sqlite3
import requests
import time
import json

STORE_CODE = 'de'
BASE_URL   = 'https://itunes.apple.com/'+STORE_CODE+'/lookup?'

cache_db = sqlite3.connect("api_cache.db")
cache_db.text_factory = str

t_last_request = None


def cache_api_response(resp, duration):
    """Cache a iTunes API response.

    :param resp The response to cache
    :param duration The time period in seconds for which to cache the data"""
    current_time = int(time.time())
    valid_until  = current_time + duration

    encoded_resp = json.dumps(resp)

    c = cache_db.cursor()
    c.execute('INSERT INTO cache VALUES (?, ?)', (valid_until, encoded_resp, ))
    cache_db.commit()


def delete_expired_responses():
    current_time = int(time.time())

    c = cache_db.cursor()
    c.execute('DELETE FROM cache WHERE valid_until < ?', (current_time, ))
    cache_db.commit()


def get_cached_api_response(**kwargs):
    """Lookup a response in the cache.

    :param kwargs Matching values. This dictionary is used to find a match to the query.
    :returns The json response, if one was found, else None"""
    delete_expired_responses()

    current_time = int(time.time())

    c = cache_db.cursor()
    c.execute('SELECT response FROM cache WHERE valid_until > ?', (current_time, ))
    results = c.fetchall()
    if results:
        for result in results:
            resp = json.loads(result[0])
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
    # Make sure we don't send too many requests.
    global t_last_request

    try:
        current_time = int(time.time())
        if current_time - t_last_request < 5:
            time.sleep(5 - (current_time - t_last_request))
        t_last_request = int(time.time())

        response = requests.get(request_url)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'))
    except:
        return None


def lookup_in_cache(**kwargs):
    if kwargs.get('no-cached', False):
        return None

    if kwargs.get('bundleId', None):
        return get_cached_api_response(bundleId = kwargs.get('bundleId'))

    if kwargs.get('trackId', None):
        return get_cached_api_response(trackId = kwargs.get('trackId'))

    return None


def lookup_metadata(**kwargs):
    if not kwargs.get('bundleId', False) and not kwargs.get('trackId', False):
        raise ValueError('Invalid usage of lookup metadata function.')

    cached_response = lookup_in_cache(kwargs)
    if cached_response:
        return cached_response

    if 'bundleId' in kwargs:
        parameter_str = 'bundleId=' + kwargs['bundleId']
    else:
        parameter_str = 'id=' + kwargs['trackId']

    request_url = _construct_url(parameter_str)
    result = None
    response = send_request(request_url)
    if response:
        if response["resultCount"] >= 1:
            result = response['results'][0]

        if kwargs.get('cache', False):
            # By default, cache responses for two hour.
            cache_api_response(result, 2 * 3600)

    return result
