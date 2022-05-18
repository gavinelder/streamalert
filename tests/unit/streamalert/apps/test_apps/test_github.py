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
import os
from mock import Mock, patch
from moto import mock_ssm
from nose.tools import (assert_equal, assert_count_equal)

from streamalert.apps._apps.github import GithubApp

from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(GithubApp, 'type', Mock(return_value='type'))
class TestGithubApp:
    """Test class for the GithubApp"""
    # pylint: disable=protected-access,no-self-use

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'github_audit'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = GithubApp(self._event, self._context)
        self._app._config.auth['gh-logs'] = 'all'
        self._app._config.auth['gh-app-identifier'] = '12345'
        self._app._config.auth['gh-organization'] = 'example'
        self._app._config.auth['gh-private-key'] = '{}'

    @staticmethod
    def _get_sample_access_logs():
        """Sample logs"""
        return {
            "@timestamp": 1628467207271,
            "action": "git.clone",
            "actor": "user",
            "actor_location": {
                "country_code": "GB"
            },
            "business": "example-org",
            "org": "example-org",
            "repo": "example-org/example-repo",
            "repository": "example-org/example-repo",
            "repository_public": "false",
            "transport_protocol": 2,
            "transport_protocol_name": "ssh",
            "user": ""
        }

    def test_sleep(self):
        """GithubApp - Sleep Seconds"""
        assert_equal(self._app._sleep_seconds(), 0)

    def test_date_formatter(self):
        """GithubApp -  Date Formatter"""
        assert_equal(self._app.date_formatter(), '%Y-%m-%dT%H:%M:%S')

    def test_required_auth_info(self):
        """GithubApp - Gather Logs, Bad Response"""
        assert_count_equal(self._app._required_auth_info().keys(),
                           {'gh-logs', 'gh-organization', 'gh-app-identifier', 'gh-private-key'})
