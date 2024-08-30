import pytest
from unittest import mock
from unittest.mock import MagicMock

from diagnose.redis_instance import RedisInstance, ArchitectureType
from diagnose.exceptions import ConnectInfoError, InstanceError, WhiteListError


@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("diagnose.redis_instance.logger") as logger:
        yield logger


class TestRedisInstance:
    @pytest.fixture(autouse=True)
    def init_advanced_mode(self):
        instance_info = {
            "InstanceStatus": "Normal",
            "ArchitectureType": "cluster",
            "ZoneId": "ZoneId",
            "RegionId": "RegionId"
        }
        network_info = {
            "NetInfoItems": {
                "InstanceNetInfo": [
                    {
                        "IPType": "Private",

                        "VPCId": "vpc-id",
                        "VSwitchId": "vsw-id",
                        "Port": "6379",
                        "DirectConnection": 0,
                        "ConnectionString": "i-12345678.redis.rds.aliyuncs.com",
                        "IPAddress": "172.18.18.18"
                    },
                    {
                        "IPType": "Public",
                        "VPCId": "",
                        "VSwitchId": "",
                        "Port": "6379",
                        "DirectConnection": 0,
                        "ConnectionString": "i-12345678pd.redis.rds.aliyuncs.com",
                        "IPAddress": "39.39.39.39"
                    }
                ]
            },
            "InstanceNetworkType": "VPC"
        }

        self.mock_sdk = MagicMock()
        self.mock_sdk.describe_instance_attribute.return_value = instance_info
        self.mock_sdk.describe_dbinstance_net_info.return_value = network_info
        self.mock_sdk.describe_security_ips.return_value = ["127.0.0.1", "192.168.0.0/16", "114.118.0.0/16"]
        self.mock_sdk.describe_global_security_ipgroup_relation.return_value = ["192.165.0.0/16"]
        self.mock_sdk.describe_security_group_configuration.return_value = [
                                                                    {
                                                                        "SecurityGroupId": "sg-group-id",
                                                                        "RegionId": "RegionId",
                                                                        "NetType": "vpc"
                                                                    }
                                                                            ]

    def test_get_redis_instance_info(self):
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)

            # Test get basic info
            assert redis_instance.region_id == "RegionId"
            assert redis_instance.zone_id == "ZoneId"
            assert redis_instance.architecture_type == ArchitectureType.CLUSTER
            assert redis_instance.instance_status == "Normal"

            # Test network info
            assert redis_instance.network_type == "VPC"
            assert redis_instance.vpc_id == "vpc-id"
            assert redis_instance.v_switch_id == "vsw-id"
            private_address = redis_instance.private_connection_info
            public_address = redis_instance.public_connection_info
            assert len(private_address) == 1
            assert len(public_address) == 1
            assert private_address[0].get("address") == "i-12345678.redis.rds.aliyuncs.com"
            assert private_address[0].get("ip") == "172.18.18.18"
            assert private_address[0].get("port") == 6379
            assert not private_address[0].get("is_direct_connection")

            assert public_address[0].get("address") == "i-12345678pd.redis.rds.aliyuncs.com"
            assert public_address[0].get("ip") == "39.39.39.39"
            assert public_address[0].get("port") == 6379
            assert not public_address[0].get("is_direct_connection")

            # Test ip whitelist
            assert redis_instance.ip_whitelist == ["127.0.0.1", "192.168.0.0/16", "114.118.0.0/16", "192.165.0.0/16"]

            # Test security group
            assert redis_instance.security_group == [
                                                        {
                                                            "SecurityGroupId": "sg-group-id",
                                                            "RegionId": "RegionId",
                                                            "NetType": "vpc"
                                                        }
                                                    ]

    def test_get_connection_address(self):
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            assert redis_instance.get_connection_address() == ["i-12345678.redis.rds.aliyuncs.com",
                                                               "i-12345678pd.redis.rds.aliyuncs.com"]

    def test_can_connect_via_intranet_address(self):
        client_wo_ecs = MagicMock()
        client_wo_ecs.ecs = None

        client_wrong_ecs_vpc = MagicMock()
        client_wrong_ecs_vpc.ecs = MagicMock()
        client_wrong_ecs_vpc.ecs.vpc_id = "vpc-id1"
        client_wrong_ecs_vpc.ecs.region_id = "RegionId"

        client_wrong_region_id = MagicMock()
        client_wrong_region_id.ecs = MagicMock()
        client_wrong_region_id.ecs.vpc_id = "vpc-id"
        client_wrong_region_id.ecs.region_id = "RegionId1"

        client_success = MagicMock()
        client_success.ecs = MagicMock()
        client_success.ecs.vpc_id = "vpc-id"
        client_success.ecs.region_id = "RegionId"

        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            print(redis_instance.vpc_id)
            print(redis_instance.region_id)
            assert redis_instance.can_connect_via_intranet_address(client_success)
            assert not redis_instance.can_connect_via_intranet_address(client_wo_ecs)
            assert not redis_instance.can_connect_via_intranet_address(client_wrong_region_id)
            assert not redis_instance.can_connect_via_intranet_address(client_wrong_ecs_vpc)

    def test_diagnose_connection_info(self):
        # Successfully Connected via public connection address
        client = MagicMock()
        client.connection_address = "i-12345678pd.redis.rds.aliyuncs.com"
        client.connection_port = 6379
        client.connect_ip = "39.39.39.39"
        client.ecs = None
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_connection_info(client)

        # Successfully Connected via private connection address
        client = MagicMock()
        client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        client.connection_port = 6379
        client.connect_ip = "172.18.18.18"
        client.ecs = MagicMock()
        client.ecs.region_id = "RegionId"
        client.ecs.vpc_id = "vpc-id"
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_connection_info(client)

        # Wrong connection address
        client = MagicMock()
        client.connection_address = "i-123456789.redis.rds.aliyuncs.com"
        client.connection_port = 6379
        client.connect_ip = "172.18.18.18"
        client.ecs = MagicMock()
        client.ecs.region_id = "RegionId"
        client.ecs.vpc_id = "vpc-id"
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(ConnectInfoError) as exc_info:
                redis_instance.diagnose_connection_info(client)
                assert exc_info.type == "address"

        # Wrong connection port
        client = MagicMock()
        client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        client.connection_port = 6370
        client.connect_ip = "172.18.18.18"
        client.ecs = MagicMock()
        client.ecs.region_id = "RegionId"
        client.ecs.vpc_id = "vpc-id"
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(ConnectInfoError) as exc_info:
                redis_instance.diagnose_connection_info(client)
                assert exc_info.type == "port"

        # Wrong connection ip
        client = MagicMock()
        client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        client.connection_port = 6379
        client.connect_ip = "172.18.18.10"
        client.ecs = MagicMock()
        client.ecs.region_id = "RegionId"
        client.ecs.vpc_id = "vpc-id"
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(ConnectInfoError) as exc_info:
                redis_instance.diagnose_connection_info(client)
                assert exc_info.type == "ip"

        # Wrong network
        client = MagicMock()
        client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        client.connection_port = 6379
        client.connect_ip = "172.18.18.10"
        client.ecs = None
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(ConnectInfoError) as exc_info:
                redis_instance.diagnose_connection_info(client)
                assert exc_info.type == "ip"

    def test_diagnose_whitelist(self):
        # Successfully Connected via private connection address
        private_client = MagicMock()
        private_client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        private_client.ecs = None
        private_client.private_ips = ["192.168.0.10"]
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_whitelist(private_client)

        # The client and redis instance are configured with the same ecs security group
        private_client_with_same_ecs_sg = MagicMock()
        private_client_with_same_ecs_sg.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        private_client_with_same_ecs_sg.ecs = MagicMock
        security_group = MagicMock()
        security_group.region_id = "RegionId"
        security_group.security_group_id = "sg-group-id"
        private_client_with_same_ecs_sg.ecs.security_groups = [security_group]
        private_client_with_same_ecs_sg.ecs.private_ips = ["172.168.0.10"]
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_whitelist(private_client_with_same_ecs_sg)

        # Fail to Connect via private connection address
        private_client = MagicMock()
        private_client.connection_address = "i-12345678.redis.rds.aliyuncs.com"
        private_client.ecs = None
        private_client.private_ips = ["192.111.0.10"]
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(WhiteListError):
                redis_instance.diagnose_whitelist(private_client)

        # Successfully Connected via public connection address
        public_client = MagicMock()
        public_client.connection_address = "i-12345678pd.redis.rds.aliyuncs.com"
        public_client.ecs = None
        public_client.public_ips = ["114.118.0.10"]
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_whitelist(public_client)

        # Fail to Connect via public connection address
        public_client = MagicMock()
        public_client.connection_address = "i-12345678pd.redis.rds.aliyuncs.com"
        public_client.ecs = None
        public_client.public_ips = ["114.111.0.10"]
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            with pytest.raises(WhiteListError):
                redis_instance.diagnose_whitelist(public_client)

    def test_diagnose_instance_status(self):
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            redis_instance = RedisInstance(instance_id="i-12345678", advanced_mode=True)
            redis_instance.diagnose_instance_status()
            with pytest.raises(InstanceError):
                redis_instance.instance_status = "Creating"
                redis_instance.diagnose_instance_status()
            with pytest.raises(InstanceError):
                redis_instance.instance_status = "Error"
                redis_instance.diagnose_instance_status()
            with pytest.raises(InstanceError):
                redis_instance.instance_status = "Released"
                redis_instance.diagnose_instance_status()
