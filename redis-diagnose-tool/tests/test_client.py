from diagnose.client import Client
from diagnose.exceptions import ConnectInfoError, NameserverError, EcsSecurityGroupError
from diagnose.diagnostic_report import ConnectionDiagnosticReport
from diagnose.notification_template import DNSResolutionNotification

import pytest
from unittest import mock


@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("diagnose.client.logger") as logger:
        yield logger


class TestClient:
    @pytest.fixture
    def init_success(self):
        with mock.patch("diagnose.utils.get_system_info", return_value=("Linux", "x86_64")):
            with mock.patch("diagnose.utils.resolve_host", return_value="1.1.1.1"):
                with mock.patch("diagnose.utils.get_public_ip_address", return_value="114.111.0.10"):
                    with mock.patch("diagnose.utils.get_ipv4_interfaces", return_value=[{"ip_address": "192.168.10.1"}]):
                            self.client = Client("i-12345678pd.redis.rds.aliyuncs.com",
                                                 6379,
                                                 ecs_instance_id=None,
                                                 advanced_mode=True)

    @pytest.fixture
    def init_dns_fail(self):
        with mock.patch("diagnose.utils.get_system_info", return_value=("Linux", "x86_64")):
            with mock.patch("diagnose.utils.resolve_host", return_value=None):
                with mock.patch("diagnose.utils.get_public_ip_address", return_value="114.111.0.10"):
                    with mock.patch("diagnose.utils.get_ipv4_interfaces", return_value=[{"ip_address": "192.168.10.1"}]):
                            self.client = Client("i-12345678pd.redis.rds.aliyuncs.com",
                                                 6379,
                                                 ecs_instance_id=None,
                                                 advanced_mode=True)

    def test_get_client_detail(self, init_success):
        assert self.client._system_type == "Linux"
        assert self.client.public_ips == ["114.111.0.10"]
        assert self.client.private_ips == ["192.168.10.1"]

    def test_diagnose_dns(self, init_dns_fail):
        # No nameserver
        with mock.patch("diagnose.utils.read_resolve_config", return_value=[]):
            with pytest.raises(NameserverError):
                self.client.diagnose_dns(["i-12345678pd.redis.rds.aliyuncs.com", "i-12345678.redis.rds.aliyuncs.com"])

        # Other error
        with mock.patch("diagnose.utils.read_resolve_config", return_value=["3.3.3.3"]):
            self.client.diagnose_dns(["i-12345678pd.redis.rds.aliyuncs.com", "i-12345678.redis.rds.aliyuncs.com"])
            assert ConnectionDiagnosticReport.warnings[-1] == DNSResolutionNotification.no_exception_warning()

        # Wrong connection address
        self.client._connection_address = "i-12345678p.redis.rds.aliyuncs.com"
        with pytest.raises(ConnectInfoError) as exc_info:
            self.client.diagnose_dns(["i-12345678pd.redis.rds.aliyuncs.com", "i-12345678.redis.rds.aliyuncs.com"])
            assert exc_info.type == "address"

    def test_diagnose_connection_interception(self, init_success):
        with mock.patch("diagnose.utils.can_establish_tcp_connection", return_value=False):
            ecs = mock.MagicMock()
            ecs.diagnose_security_group.side_effect = EcsSecurityGroupError("egress",
                                                                            "37.37.37.37",
                                                                            6379)
            self.client._ecs = ecs
            with pytest.raises(EcsSecurityGroupError):
                self.client.diagnose_connection_interception()


