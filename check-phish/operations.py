""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
"""

import json
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('check-phish')


class CheckPhish(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            headers = {'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_job_id(config, params):
    job_id = CheckPhish(config)
    payload = {"apiKey": config.get('api_key'), "urlInfo": {"url": params.get('url')},
               "scanType": params.get('scanType').lower()}
    return job_id.make_request(endpoint='api/neo/scan', method='POST', data=json.dumps(payload))


def get_url_info(config, params):
    url_info = CheckPhish(config)
    jobID = get_job_id(config, params)
    payload = {"apiKey": config.get('api_key'), "jobID": jobID['jobID'], "insights": params.get('insights')}
    return url_info.make_request(endpoint='api/neo/scan/status', method='POST', data=json.dumps(payload))


def _check_health(config):
    try:
        params = {'url': 'https://webafit.noip.us/', 'scanType': 'full', 'insights': False}
        res = get_job_id(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_url_info': get_url_info
}
