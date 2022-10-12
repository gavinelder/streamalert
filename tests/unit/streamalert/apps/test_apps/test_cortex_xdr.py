import os

from mock import patch
from moto import mock_ssm
from nose.tools import assert_equal

from streamalert.apps._apps.cortex_xdr import CortexAgentsAuditApp
from streamalert.apps._apps.cortex_xdr import CortexManagementAuditApp

from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
class TestCortexAgentsAuditApp:
    """Test class for the CortexAgentsAuditApp"""
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'cortex_xdr_agent_audit'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = CortexAgentsAuditApp(self._event, self._context)

    def test_required_auth_info(self):
        """CortexAgentsAuditApp - Required Auth Info"""
        assert_equal(list(self._app.required_auth_info()), ['key', 'key_id'])

    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample cortex xdr agent audit logs."""

        return [{
            "TIMESTAMP": 1631154959169 + i,
            "RECEIVEDTIME": 1631155032992.261 + i,
            "ENDPOINTID": "15020e8280834297ab7fcf7e10423374",
            "ENDPOINTNAME": "MACHINE",
            "DOMAIN": "WORKGROUP",
            "CATEGORY": "Monitoring",
            "TYPE": "Agent Service",
            "SUBTYPE": "Stop",
            "SEVERITY": "SEV_040_HIGH",
            "RESULT": "N/A",
            "REASON": None,
            "DESCRIPTION": "XDR service cyserver was stopped on MACHINE",
            "XDRVERSION": "7.4.1.31675"
        } for i in range(count)]


@mock_ssm
class TestCortexManagementAuditApp:
    """Test class for the CortexManagementsAuditApp"""
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'cortex_xdr_management_audit'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = CortexManagementAuditApp(self._event, self._context)

    def test_required_auth_info(self):
        """CortexManagementAuditApp - Required Auth Info"""
        assert_equal(list(self._app.required_auth_info()), ['key', 'key_id'])

    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample cortex xdr agent audit logs."""

        return [{
            "AUDIT_OWNER_EMAIL": "mickeymouse@improbable.io",
            "AUDIT_ASSET_JSON": None,
            "AUDIT_ASSET_NAMES": "",
            "AUDIT_HOSTNAME": None,
            "AUDIT_RESULT": "SUCCESS",
            "AUDIT_REASON": None,
            "AUDIT_DESCRIPTION": None,
            "AUDIT_ENTITY": "AUTH",
            "AUDIT_ENTITY_SUBTYPE": "Login",
            "AUDIT_SESSION_ID": None,
            "AUDIT_CASE_ID": None,
            "AUDIT_INSERT_TIME": 1632092400000 + 10 * i,
            "AUDIT_SEVERITY": "SEV_010_INFO"
        } for i in range(count)]
