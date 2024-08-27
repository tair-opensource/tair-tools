import json
from enum import Enum
from typing import List, Mapping, Any, Union, Callable
import functools

from Tea.core import TeaCore
from alibabacloud_tea_openapi import models as open_api_models

from alibabacloud_r_kvstore20150101 import models as r_kvstore_20150101_models
from alibabacloud_r_kvstore20150101.client import Client as R_kvstore20150101Client

from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_ecs20140526 import models as ecs_20140526_models

from diagnose.exceptions import SDKError, InternalError
from diagnose.logger_config import sdk_logger
from diagnose.notification_template import ErrorNotification


def sdk_wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        arg_str = ", ".join([repr(a) for a in args if not isinstance(a, SDK)] + [f"{k}={v!r}" for k, v in kwargs.items()])
        sdk_logger.info(f"Calling {func.__name__}({arg_str})")
        try:
            result = func(*args, **kwargs)
            sdk_logger.info(f"Successfully call {func.__name__}, return: {result}")
            return result
        except Exception as e:
            sdk_logger.error(f"Exception occurred while calling {func.__name__}: {e}")
            if "InvalidAccessKeyId" in str(e):
                error_info = f"{str(e)}, {ErrorNotification.sdk_invalid_ak_error()}"
            elif "IncompleteSignature" in str(e):
                error_info = f"{str(e)}, {ErrorNotification.sdk_invalid_sk_error()}"
            elif "NameResolutionError" in str(e):
                error_info = f"{str(e)}, {ErrorNotification.sdk_service_address_error()}"
            elif "Forbidden.RAM" in str(e):
                error_info = f"{str(e)}, {ErrorNotification.sdk_service_forbidden_error()}"
            else:
                error_info = f"{str(e)}"
            raise SDKError(error_info)
    return wrapper


class SDK:
    pass


class EcsSDK(SDK):
    def __init__(self, client: Ecs20140526Client):
        self._client = client

    @sdk_wrapper
    def describe_instance_attribute(self, instance_id: str) -> Mapping[str, Any]:
        request = ecs_20140526_models.DescribeInstanceAttributeRequest(instance_id=instance_id)
        response = self._client.describe_instance_attribute(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            return response_map["body"]
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_security_group_attribute(
            self,
            region_id: str,
            security_group_id: str,
            direction: str = "all",
    ) -> map:
        if direction not in ["all", "ingress", "egress"]:
            raise InternalError("Invalid direction: {}, "
                                "direction must be one of 'all', 'ingress', 'egress'".format(direction))
        request = ecs_20140526_models.DescribeSecurityGroupAttributeRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            direction=direction,
            max_results=1000,
        )
        response = self._client.describe_security_group_attribute(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            return response_map["body"]
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_security_groups(self, region_id: str, security_group_ids: List[str]) -> map:
        request = ecs_20140526_models.DescribeSecurityGroupsRequest(
            region_id=region_id,
            security_group_ids=json.dumps(security_group_ids),
            max_results=100,
        )
        response = self._client.describe_security_groups(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            return response_map["body"]
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))


class RedisSDK(SDK):
    def __init__(self, client: R_kvstore20150101Client):
        self._client = client

    @sdk_wrapper
    def describe_instance_attribute(self, instance_id: str) -> map:
        request = r_kvstore_20150101_models.DescribeInstanceAttributeRequest(instance_id=instance_id)
        response = self._client.describe_instance_attribute(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            response_body_map = response_map["body"]
            instance_info_list = response_body_map["Instances"]["DBInstanceAttribute"]
            if len(instance_info_list) > 0:
                instance_info = instance_info_list[0]
                if len(instance_info_list) > 1:
                    sdk_logger.warning("Multiple Redis instances found, use the first one, "
                                       "instance id: {}".format(instance_id))
                return instance_info
            else:
                raise SDKError("Instance attribute not found, instance id: {}".format(instance_id))
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_dbinstance_net_info(self, instance_id: str) -> Mapping[str, Any]:
        request = r_kvstore_20150101_models.DescribeDBInstanceNetInfoRequest(instance_id=instance_id)
        response = self._client.describe_dbinstance_net_info(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            response_body_map = response_map["body"]
            if len(response_body_map["NetInfoItems"]["InstanceNetInfo"]) == 0:
                raise SDKError("Instance net info not found, instance id: {}".format(instance_id))
            return response_body_map
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_security_ips(self, instance_id: str) -> List[str]:
        request = r_kvstore_20150101_models.DescribeSecurityIpsRequest(instance_id=instance_id)
        response = self._client.describe_security_ips(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            response_body_map = response_map["body"]
            security_ip_groups = response_body_map["SecurityIpGroups"]["SecurityIpGroup"]
            security_ip_list = []
            for security_ip_group in security_ip_groups:
                security_ips = security_ip_group["SecurityIpList"].split(",")
                security_ip_list.extend(security_ips)
            return security_ip_list
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_global_security_ipgroup_relation(self, region_id: str, instance_id: str) -> List[str]:
        request = r_kvstore_20150101_models.DescribeGlobalSecurityIPGroupRelationRequest(region_id=region_id,
                                                                                         dbcluster_id=instance_id)
        response = self._client.describe_global_security_ipgroup_relation(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            global_ip_list = []
            security_ip_group_rel_list = response_map["body"]["GlobalSecurityIPGroupRel"]
            for security_ip_group_rel in security_ip_group_rel_list:
                global_ip_list.extend(security_ip_group_rel["GIpList"].split(","))
            return global_ip_list
        else:
            raise SDKError("The request was not responded correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))

    @sdk_wrapper
    def describe_security_group_configuration(self, instance_id: str) -> List[Mapping[str, str]]:
        request = r_kvstore_20150101_models.DescribeSecurityGroupConfigurationRequest(instance_id=instance_id)
        response = self._client.describe_security_group_configuration(request)
        response_map = TeaCore.to_map(response)
        if response_map["statusCode"] == 200:
            return response_map["body"]["Items"]["EcsSecurityGroupRelation"]
        else:
            raise SDKError("The request was not responded  correctly, status code: {}, "
                           "request id: {}".format(response_map["statusCode"], response_map["body"]["RequestId"]))


class SDKType(Enum):
    ECS = "ecs"
    REDIS = "redis"


class SDKFactory:
    _access_key_id: str = None
    _access_key_secret: str = None
    _endpoint_map: Mapping[SDKType, Any] = dict()
    _region_id_map: Mapping[SDKType, Any] = dict()
    _sdk_map: Mapping[SDKType, SDK] = dict()

    @classmethod
    def config_sdk(
        cls,
        access_key_id: str,
        access_key_secret: str,
        endpoint_map: Mapping[SDKType, Any] = None,
        region_id_map: Mapping[SDKType, Any] = None,
    ):
        cls._access_key_id = access_key_id
        cls._access_key_secret = access_key_secret
        cls._endpoint_map = endpoint_map if endpoint_map is not None else dict()
        cls._region_id_map = region_id_map if region_id_map is not None else dict()

    @classmethod
    def get_sdk(cls, sdk_type: SDKType) -> Union[EcsSDK, RedisSDK]:
        if cls._sdk_map.get(sdk_type) is not None:
            return cls._sdk_map.get(sdk_type)

        if cls._access_key_id is None or cls._access_key_secret is None:
            raise InternalError("crate sdk: access key id and access ke secret cannot be None")

        if cls._endpoint_map.get(sdk_type) is None and cls._region_id_map.get(sdk_type) is None:
            raise InternalError("create sdk: endpoint and region_id cannot be both None")

        config = open_api_models.Config(
            access_key_id=cls._access_key_id,
            access_key_secret=cls._access_key_secret,
            connect_timeout=3000,
            read_timeout=3000,
        )
        if cls._endpoint_map.get(sdk_type) is not None:
            config.endpoint = cls._endpoint_map.get(sdk_type)
        if cls._region_id_map.get(sdk_type) is not None:
            config.region_id = cls._region_id_map.get(sdk_type)

        if sdk_type == SDKType.REDIS:
            client = R_kvstore20150101Client(config)
            redis_sdk = RedisSDK(client)
            cls._sdk_map[sdk_type] = redis_sdk
            return redis_sdk
        elif sdk_type == SDKType.ECS:
            client = Ecs20140526Client(config)
            ecs_sdk = EcsSDK(client)
            cls._sdk_map[sdk_type] = ecs_sdk
            return ecs_sdk
        else:
            raise InternalError(f"Unknown sdk type: {sdk_type}")