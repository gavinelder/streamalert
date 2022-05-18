"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
import datetime
import json
import requests
import jwt
from . import AppIntegration, get_logger, StreamAlertApp

LOGGER = get_logger(__name__)


@StreamAlertApp
class GithubApp(AppIntegration):
    """
    Github SASS Enterprise Event Collector the following requires a GH Enterprise subscription.
    https://docs.github.com/en/rest/reference/orgs#get-the-audit-log-for-an-organization

    To use this application, you should configure and install a Github Application as per
    https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps
    with the admin:org scope.
    """

    _GH_API_BASE_URL = 'https://api.github.com/orgs/{}/audit-log'
    _MAX_RESPONSE_LOGS = 100

    def __init__(self, event, context):
        super(GithubApp, self).__init__(event, context)
        self._next_page = None

    @classmethod
    def service(cls):
        return 'github'

    @classmethod
    def _type(cls):
        return 'audit'

    @classmethod
    def _required_auth_info(cls):
        """
        Setup the required authentication required to collect the Github Audit logs.
        """
        key_start = '-----BEGIN RSA PRIVATE KEY-----'
        key_end = '-----END RSA PRIVATE KEY-----'

        def keyfile_validator(keyfile):
            """Check for A PEM Formated PKCS#1 RSAPrivateKey."""
            try:
                with open(keyfile.strip(), 'r') as rsa_keyfile:
                    filecontent = rsa_keyfile.read().rstrip('\n')
            except (IOError, ValueError):
                return False
            if filecontent.startswith(key_start) and filecontent.endswith(key_end):
                # Return filecontent JSON Encoded for AWS Paramater Store compatibility.
                return json.dumps(filecontent)
            return False

        return {
            'gh-private-key': {
                'description': 'the path on disk to the Github App private key file',
                'format': keyfile_validator
            },
            'gh-organization': {
                'description': 'The name of the Github organization to query for the Audit log',
                'format': re.compile(r'^[a-zA-Z0-9\-]{1,39}$')
            },
            'gh-logs': {
                'description': 'The type of logs you would like to collect "web" "git" or "all"',
                'format': re.compile(r'^web$|^git$|^all$')
            },
            'gh-app-identifier': {
                'description': 'The GitHub App identifier (Not installation ID)',
                'format': re.compile(r'^[0-9]{5,15}')
            },
        }

    def _gather_logs(self):
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            "Content-Type": "application/json",
            "Authorization": "token %s" % self.get_auth_token(),
        }
        if self._next_page:
            params = None
            url = self._next_page
        else:
            params = {
                'order': 'asc',
                'per_page': '%s' % self._MAX_RESPONSE_LOGS,
                'include': '%s' % self._config.auth['gh-logs']
            }
            url = self._GH_API_BASE_URL.format(self._config.auth['gh-organization'])
            if self._context.get('last_log_timestamp', []):
                timestamp = int(self._context.get('last_log_timestamp'))
                search_phrase = "created:>%s" % datetime.datetime.utcfromtimestamp(
                    timestamp).strftime('%Y-%m-%dT%H:%M:%S')
                params['phrase'] = search_phrase
                LOGGER.info('[%s] search phrase is [%s]', self, search_phrase)

        try:
            result, response = self._make_get_request(full_url=url, params=params, headers=headers)
        except requests.exceptions.ConnectionError:
            LOGGER.exception('Received bad response from Github')
            return False

        if not result:
            return False

        if not response.json():
            return False

        if 'next' in response.links:
            self._more_to_poll = True
            self._next_page = response.links['next']['url']
        else:
            self._more_to_poll = False
            self._next_page = None

        resp = response.json()
        timestamp = resp[-1]['@timestamp'] / 1000

        self._context['last_log_timestamp'] = timestamp
        self._last_timestamp = timestamp

        return resp

    def create_jwt(self):
        """
        Prepares the JSON Web Token (JWT) based on the private key.
        """
        now = datetime.datetime.now()
        json_web_token_expiry = now + datetime.timedelta(minutes=9)

        payload = {
            "iat": int(now.timestamp()),
            "exp": int(json_web_token_expiry.timestamp()),
            "iss": int(self._config.auth['gh-app-identifier'])
        }
        json_web_token = jwt.encode(payload,
                                    json.loads(self._config.auth['gh-private-key']),
                                    algorithm='RS256')

        return json_web_token.decode()

    def get_auth_token(self):
        """Generates an authentication token

        Returns:
            string: Authentication Token
        """
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.create_jwt(),
        }
        # Drop any over permission grant of the Github App & fail early if scope not avaiable
        data = '{"permissions":{"organization_administration":"read"}}'
        url = 'https://api.github.com/app/installations/%s/access_tokens' % self.get_install_id()
        try:
            result, response = self._make_post_request(full_url=url, data=data, headers=headers)
        except requests.exceptions.ConnectionError:
            LOGGER.exception('Received bad response from Github')
            return False
        if not result:
            LOGGER.exception('Access denied whilst requesting installation auth token')
            return False

        if not response:
            return False

        return response['token']

    def get_install_id(self):
        """Returns the instalation ID of the Github App within the organization

        Returns:
            string: The instalation ID
        """
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': 'Bearer %s' % self.create_jwt(),
        }
        url = "https://api.github.com/app/installations"
        try:
            result, response = self._make_get_request(full_url=url, headers=headers)
        except requests.exceptions.ConnectionError:
            LOGGER.exception('Received bad response from Github')
            return False

        if not result:
            return False
        resp = response.json()
        return resp[0]['id'] if resp else False

    @classmethod
    def date_formatter(cls):
        """Github API date format: YYYY-MM-DDTHH:MM:SS"""
        return '%Y-%m-%dT%H:%M:%S'

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests.

        The Github API has a limit of 15,000 API calls per hour per user, which we will
        not hit, so return 0 here.

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return 0

    def _make_get_request(self, full_url, headers, params=None):
        """Make GET request

        This method overrides the method in AppIntegration base class to handle
        not only JSON response, and return the full response instead as we require pagination
        information from the request headers to fetch subsequent event logs.

        Args:
            full_url (str): The full url of GET request.
            headers (dict): The full headers.

        Returns:
            bool: True if GET response is valid.
            resp: Response object
        """
        response = requests.get(full_url,
                                headers=headers,
                                params=params,
                                timeout=self._DEFAULT_REQUEST_TIMEOUT)

        return self._check_http_response(response), response
