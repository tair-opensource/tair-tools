from diagnose.sdk import EcsSDK, RedisSDK, SDKFactory, SDKType
from diagnose.exceptions import SDKError, InternalError
from diagnose.notification_template import ErrorNotification

import pytest
from unittest.mock import patch, MagicMock
from unittest import mock
from Tea.model import TeaModel


@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("diagnose.sdk.sdk_logger") as logger:
        yield logger


class TestEcsSDK:
    """
        All ecs sdk calls are similar, so only one unit test of the interface describe_instance_attribute is implemented
    """
    @pytest.fixture(autouse=True)
    def init(self):
        self.ecs_sdk = EcsSDK(None)

    def _mock_client(self):
        mock_client = MagicMock()
        mock_client.describe_instance_attribute.return_value = TeaModel()
        self.ecs_sdk._client = mock_client

    def _mock_client_with_exception(self, exception_info):
        mock_client = MagicMock()
        mock_client.describe_instance_attribute.side_effect = Exception(exception_info)

        self.ecs_sdk._client = mock_client

    def test_describe_instance_attribute_success(self):
        self._mock_client()
        # Mock the response from the SDK client
        mock_response = {
            "statusCode": 200,
            "body": {
                "ZoneId": "ZoneId",
                "RegionId": "RegionId",
            }
        }
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            mock_to_map.return_value = mock_response
            result = self.ecs_sdk.describe_instance_attribute(instance_id="i-12345678")
            assert result == mock_response["body"]

    def test_describe_instance_attribute_failure(self):
        self._mock_client()
        mock_response = {
            "statusCode": 404,
            "body": {
                "RequestId": "req-12345678",
            }
        }
        # Call the method and expect it to raise an SDKError
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            mock_to_map.return_value = mock_response
            with pytest.raises(SDKError) as exc_info:
                self.ecs_sdk.describe_instance_attribute(instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert str(exc_info.value) == expected_error_message

    def test_test_describe_instance_attribute_throw_exception(self):
        # Mock the response from the SDK client
        mock_response = {
            "statusCode": 200,
            "body": {
                "ZoneId": "ZoneId",
                "RegionId": "RegionId",
            }
        }
        instance_id = "i-12345678"
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            mock_to_map.return_value = mock_response

            # Invalid ak
            self._mock_client_with_exception("InvalidAccessKeyId")
            with pytest.raises(SDKError) as exc_info:
                self.ecs_sdk.describe_instance_attribute(instance_id)
                assert ErrorNotification.sdk_invalid_ak_error() in str(exc_info.value)

            # Invalid sk
            self._mock_client_with_exception("IncompleteSignature")
            with pytest.raises(SDKError) as exc_info:
                self.ecs_sdk.describe_instance_attribute(instance_id)
                assert ErrorNotification.sdk_invalid_sk_error() in str(exc_info.value)

            # Invalid service address
            self._mock_client_with_exception("NameResolutionError")
            with pytest.raises(SDKError) as exc_info:
                self.ecs_sdk.describe_instance_attribute(instance_id)
                assert ErrorNotification.sdk_service_address_error() in str(exc_info.value)

            # Forbidden
            self._mock_client_with_exception("Forbidden.RAM")
            with pytest.raises(SDKError) as exc_info:
                self.ecs_sdk.describe_instance_attribute(instance_id)
                assert ErrorNotification.sdk_service_forbidden_error() in str(exc_info.value)


class TestRedisSDK:
    @pytest.fixture(autouse=True)
    def init(self):
        self.redis_sdk = RedisSDK(None)
        self._mock_client()

    def _mock_client(self):
        mock_client = MagicMock()
        mock_client.describe_instance_attribute.return_value = TeaModel()
        mock_client.describe_dbinstance_net_info.return_value = TeaModel()
        mock_client.describe_security_ips.return_value = TeaModel()
        mock_client.describe_global_security_ipgroup_relation.return_value = TeaModel()
        mock_client.describe_security_group_configuration.return_value = TeaModel()
        self.redis_sdk._client = mock_client

    def test_describe_instance_attribute(self):
        attr_map_1 = {"ZoneId": "ZoneId1", "RegionId": "RegionId1"}
        attr_map_2 = {"ZoneId": "ZoneId2", "RegionId": "RegionId2"}
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            # No instance attribute
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "Instances": {
                        "DBInstanceAttribute": []

                    }
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_instance_attribute(instance_id="i-12345678")
                assert "Instance attribute not found" in str(exc_info)

            # Exact one instance attribute
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "Instances": {
                        "DBInstanceAttribute": [attr_map_1]
                    }
                }
            }
            instance_info = self.redis_sdk.describe_instance_attribute(instance_id="i-12345678")
            assert instance_info == attr_map_1

            # Multiple instance attributes, return the first one
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "Instances": {
                        "DBInstanceAttribute": [attr_map_2, attr_map_1]
                    }
                }
            }
            instance_info = self.redis_sdk.describe_instance_attribute(instance_id="i-12345678")
            assert instance_info == attr_map_2

            # Error status code
            mock_to_map.return_value = {
                "statusCode": 404,
                "body": {
                    "RequestId": "req-12345678",
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_instance_attribute(instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert str(exc_info.value) == expected_error_message

    def test_describe_dbinstance_net_info(self):
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            # Success
            mock_map = {
                "statusCode": 200,
                "body": {
                    "RequestId": "req-12345678",
                    "NetInfoItems": {
                        "InstanceNetInfo": [{"IPAddress": "127.0.0.1", "IPType": "Private"}]
                    },
                    "InstanceNetworkType": "VPC"
                }
            }
            mock_to_map.return_value = mock_map
            net_info = self.redis_sdk.describe_dbinstance_net_info(instance_id="i-12345678")
            assert net_info == mock_map["body"]

            # No net info
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "RequestId": "req-12345678",
                    "NetInfoItems": {
                        "InstanceNetInfo": []
                    }
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_dbinstance_net_info(instance_id="i-12345678")
                expected_error_message = "Instance net info not found, instance id: i-12345678"
                assert expected_error_message == str(exc_info.value)

            # Error status code
            mock_to_map.return_value = {
                "statusCode": 404,
                "body": {
                    "RequestId": "req-12345678",
                    "NetInfoItems": {
                        "InstanceNetInfo": []
                    }
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_dbinstance_net_info(instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert expected_error_message == str(exc_info.value)

    def test_describe_security_ips(self):
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            # Success
            mock_map = {
                "statusCode": 200,
                "body": {
                    "RequestId": "req-12345678",
                    "SecurityIpGroups": {
                        "SecurityIpGroup": [
                            {
                                "SecurityIpGroupAttribute": "",
                                "SecurityIpList": "1.1.1.1,127.0.0.1",
                                "SecurityIpGroupName": "default"
                            },
                            {
                                "SecurityIpGroupAttribute": "hidden",
                                "SecurityIpList": "2.2.2.2/4,3.3.3.3/4",
                                "SecurityIpGroupName": "default2"
                            }
                        ]
                    }
                }
            }
            mock_to_map.return_value = mock_map
            security_ips = self.redis_sdk.describe_security_ips(instance_id="i-12345678")
            assert security_ips == ["1.1.1.1", "127.0.0.1", "2.2.2.2/4", "3.3.3.3/4"]

            # Error status code
            mock_map = {
                "statusCode": 404,
                "body": {
                    "RequestId": "req-12345678",
                }
            }
            mock_to_map.return_value = mock_map
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_security_ips(instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert expected_error_message == str(exc_info.value)

    def test_describe_global_security_ipgroup_relation(self):
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            # Success
            security_group_relation = {
                                      "GlobalIgName": "GlobalIgName",
                                      "GIpList": "1.1.1.1,2.2.2.2",
                                      "GlobalSecurityGroupId": "g-GlobalSecurityGroupId",
                                      "RegionId": "RegionId"
                                        }
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "RequestId": "req-12345678",
                    "DBClusterId": "i-12345678",
                    "GlobalSecurityIPGroupRel": [security_group_relation]
                }
            }
            result = self.redis_sdk.describe_global_security_ipgroup_relation(region_id="region_id",
                                                                              instance_id="i-12345678")
            assert result == ["1.1.1.1", "2.2.2.2"]

            # Error status code
            mock_to_map.return_value = {
                "statusCode": 404,
                "body": {
                    "RequestId": "req-12345678",
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_global_security_ipgroup_relation(region_id="region_id",
                                                                         instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert expected_error_message == str(exc_info.value)

    def test_describe_security_group_configuration(self):
        with patch("diagnose.sdk.TeaCore.to_map") as mock_to_map:
            # Success
            ecs_security_group_relation = {
                                            "SecurityGroupId": "SecurityGroupId123",
                                            "RegionId": "RegionId",
                                            "NetType": "vpc"
                                         }
            mock_to_map.return_value = {
                "statusCode": 200,
                "body": {
                    "RequestId": "req-12345678",
                    "Items": {
                        "EcsSecurityGroupRelation": [ecs_security_group_relation]
                    }
                }
            }
            result = self.redis_sdk.describe_security_group_configuration(instance_id="i-12345678")
            assert result == [ecs_security_group_relation]

            # Error status code
            mock_to_map.return_value = {
                "statusCode": 404,
                "body": {
                    "RequestId": "req-12345678",
                }
            }
            with pytest.raises(SDKError) as exc_info:
                self.redis_sdk.describe_security_group_configuration(instance_id="i-12345678")
                expected_error_message = ("The request was not responded correctly, status code: 404,"
                                          " request id: req-12345678")
                assert expected_error_message == str(exc_info.value)


def test_get_sdk():
    # No ak and sk
    with pytest.raises(InternalError) as exc_info:
        SDKFactory.get_sdk(SDKType.REDIS)
        expected_error_message = "crate sdk: access key id and access ke secret cannot be None"
        assert expected_error_message == str(exc_info.value)

    SDKFactory.config_sdk("access_key_id", "access_key_secret")

    # No endpoint and region id
    with pytest.raises(InternalError) as exc_info:
        SDKFactory.get_sdk(SDKType.REDIS)
        expected_error_message = "create sdk: endpoint and region_id cannot be both None"
        assert expected_error_message == str(exc_info.value)

    # Success
    SDKFactory.config_sdk("access_key_id",
                          "access_key_secret",
                          {SDKType.REDIS: "endpoint"},
                          {SDKType.REDIS: "region_id"})
    redis_sdk = SDKFactory.get_sdk(sdk_type=SDKType.REDIS)
    assert redis_sdk is not None
    assert isinstance(redis_sdk, RedisSDK)