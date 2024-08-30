from enum import Enum
from typing import List, Mapping, Any, Union, Optional
import copy
import time
import math
from tqdm import tqdm

import redis

from diagnose.client import Client
from diagnose.sdk import SDKFactory, SDKType
from diagnose.exceptions import ConnectInfoError, WhiteListError, InstanceError, InternalError, ServerError
from diagnose import utils
from diagnose.logger_config import logger
from diagnose.diagnostic_report import (
    ConnectionDiagnosticReport,
    ServerDiagnosticReport,
    ProcessReport,
    Check,
    AuditItem,
)
from diagnose.notification_template import (
    RedisInstanceNotification,
    ConnectionInfoNotification,
    WhitelistNotification,
    InstanceStatusNotification,
    ServerDetectionNotification,
)


class ConnectionType(Enum):
    DIRECT = "direct"
    PROXY = "proxy"


class ArchitectureType(Enum):
    STANDARD = "standard"
    CLUSTER = "cluster"
    RWSPLIT = "rwsplit"


class RedisInstance:
    def __init__(self, instance_id: str = None, advanced_mode: bool = False):
        self.instance_id = instance_id
        self.advanced_mode = advanced_mode
        self.region_id = None
        self.zone_id = None
        self.network_type = None
        self.public_connection_info: List[Mapping[str, Any]] = []
        self.private_connection_info: List[Mapping[str, Any]] = []
        self.vpc_id = None
        self.v_switch_id = None
        self.instance_status = None
        self.instance_type = None
        self.architecture_type = None
        self.total_node_count = 0
        self.ip_whitelist = []
        self.security_group: List[Mapping[str, str]] = []

        if self.instance_id is not None and self.advanced_mode:
            logger.info(ProcessReport.get_arrow_line(yes=True))
            logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
            logger.info(ProcessReport.gen_process_rectangle(RedisInstanceNotification.redis_instance_info_log()))
            self._get_instance_basic_info()
            self._get_instance_network_info()
            self._get_instance_ip_whitelist()
            self._get_security_group()

    def _get_instance_basic_info(self):
        redis_sdk = SDKFactory.get_sdk(SDKType.REDIS)
        instance_info = redis_sdk.describe_instance_attribute(self.instance_id)
        self.region_id = instance_info.get("RegionId")
        self.zone_id = instance_info.get("ZoneId")
        self.instance_status = instance_info.get("InstanceStatus")
        for architecture_type in ArchitectureType:
            if architecture_type.value == instance_info.get("ArchitectureType"):  # cluster, rwsplit, standard
                self.architecture_type = architecture_type
                break

    def _get_instance_network_info(self):
        redis_sdk = SDKFactory.get_sdk(SDKType.REDIS)
        instance_network_info = redis_sdk.describe_dbinstance_net_info(self.instance_id)
        self.network_type = instance_network_info.get("InstanceNetworkType")
        net_info_list = instance_network_info.get("NetInfoItems", dict()).get("InstanceNetInfo", list())
        for net_info in net_info_list:
            if net_info.get("IPType") == "Private":
                if net_info.get("IPAddress") is not None:
                    self.private_connection_info.append({"address": net_info.get("ConnectionString"),
                                                         "port": int(net_info.get("Port")),
                                                         "ip": net_info.get("IPAddress"),
                                                         "is_direct_connection": net_info.get("DirectConnection") == 1})
                if self.network_type == "VPC":
                    self.vpc_id = net_info.get("VPCId")
                    self.v_switch_id = net_info.get("VSwitchId")
            elif net_info.get("IPType") == "Public":
                if net_info.get("IPAddress") is not None:
                    self.public_connection_info.append({"address": net_info.get("ConnectionString"),
                                                        "port": int(net_info.get("Port")),
                                                        "ip": net_info.get("IPAddress"),
                                                        "is_direct_connection": net_info.get("DirectConnection") == 1})
            elif net_info.get("IPType") == "Inner":  # Classic network
                ConnectionDiagnosticReport.add_warning(RedisInstanceNotification.classic_network_not_support_warning())

    def _get_instance_ip_whitelist(self):
        redis_sdk = SDKFactory.get_sdk(SDKType.REDIS)
        self.ip_whitelist.extend(redis_sdk.describe_security_ips(self.instance_id))
        self.ip_whitelist.extend(redis_sdk.describe_global_security_ipgroup_relation(self.region_id, self.instance_id))

    def _get_security_group(self):
        redis_sdk = SDKFactory.get_sdk(SDKType.REDIS)
        self.security_group = redis_sdk.describe_security_group_configuration(self.instance_id)

    def get_connection_address(self) -> List[str]:
        private_connection_addresses = [connection_info.get("address") for connection_info in
                                        self.private_connection_info if connection_info.get("address") is not None]
        public_connection_addresses = [connection_info.get("address") for connection_info in
                                       self.public_connection_info if connection_info.get("address") is not None]
        return [*private_connection_addresses, *public_connection_addresses]

    def diagnose_connection_info(self, client: Client):
        if not self.advanced_mode:
            ConnectionDiagnosticReport.add_warning(ConnectionInfoNotification.not_check_warning())
            return

        logger.info(ProcessReport.gen_process_rectangle(ConnectionInfoNotification.diagnose_log()))
        ConnectionDiagnosticReport.add_check(Check(ConnectionInfoNotification.check_name()))
        connection_info_check = ConnectionDiagnosticReport.get_last_check()

        # Merge public and private connection info
        candidate_connection_info = copy.deepcopy(self.private_connection_info)
        candidate_connection_info.extend(self.public_connection_info)

        # Check connection network
        private_connection_addresses = [connection_info.get("address") for connection_info in
                                        self.private_connection_info]
        if (client.connection_address in private_connection_addresses
                and client.ecs is not None
                and self.vpc_id is not None
                and not self.can_connect_via_intranet_address(client)
        ):
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            ConnectionDiagnosticReport.add_issue(ConnectionInfoNotification.intranet_access_issue())
            connection_info_check.fail()
            connection_info_check.set_detail(ConnectionInfoNotification.intranet_access_detail())
            raise ConnectInfoError("network", client.connection_address, client.connection_port)

        # Check connection address, port and ip
        correct = False
        for connection_info in candidate_connection_info:
            if client.connection_address != connection_info.get("address"):
                continue
            if client.connection_port != connection_info.get("port"):
                logger.error(ProcessReport.get_arrow_line(yes=False, message="wrong port"))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                ConnectionDiagnosticReport.add_issue(ConnectionInfoNotification.wrong_connection_port_issue())
                connection_info_check.fail()
                connection_info_check.set_detail(ConnectionInfoNotification.wrong_connection_port_detail().format(
                    connection_info.get("port"), client.connection_port))
                raise ConnectInfoError("port", client.connection_address, client.connection_port)
            if client.connect_ip != connection_info.get("ip"):
                logger.error(ProcessReport.get_arrow_line(yes=False, message="wrong ip"))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                ConnectionDiagnosticReport.add_issue(ConnectionInfoNotification.wrong_connection_ip_issue())
                connection_info_check.fail()
                connection_info_check.set_detail(ConnectionInfoNotification.wrong_connection_ip_detail().format(
                                                 connection_info.get("ip"), client.connect_ip))
                raise ConnectInfoError("ip", client.connection_address, client.connection_port)
            correct = True
        if not correct:
            logger.error(ProcessReport.get_arrow_line(yes=False, message="wrong address"))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            candidate_connection_addresses = [connection_info.get("address") for connection_info in
                                              candidate_connection_info]
            detail = ConnectionInfoNotification.wrong_connection_address_detail().format(
                ",".join(candidate_connection_addresses), client.connection_address)
            ConnectionDiagnosticReport.add_issue(ConnectionInfoNotification.wrong_connection_address_issue())
            connection_info_check.fail()
            connection_info_check.set_detail(detail)
            raise ConnectInfoError("address", client.connection_address, client.connection_port)

        # All checks succeed
        logger.info(ProcessReport.get_arrow_line(yes=True))
        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        connection_info_check.success()
        connection_info_check.set_detail(ConnectionInfoNotification.success_detail())

    def can_connect_via_intranet_address(self, client: Client):
        # The ecs and redis instances must belong to the same vpc to be connected via the intranet address
        return client.ecs is not None and client.ecs.vpc_id == self.vpc_id and client.ecs.region_id == self.region_id

    def diagnose_whitelist(self, client: Client):
        if not self.advanced_mode:
            ConnectionDiagnosticReport.add_warning(WhitelistNotification.not_check_warning())
            return

        logger.info(ProcessReport.gen_process_rectangle(WhitelistNotification.diagnose_log()))
        ConnectionDiagnosticReport.add_check(Check(WhitelistNotification.check_name()))
        whitelist_check = ConnectionDiagnosticReport.get_last_check()

        # Connect via private address, check ip whitelist and redis instance security group
        private_connection_addresses = [connection_info.get("address") for connection_info in
                                        self.private_connection_info]
        if client.connection_address in private_connection_addresses:
            for redis_security_group in self.security_group:
                if client.ecs is None:
                    break
                for ecs_security_group in client.ecs.security_groups:
                    if (redis_security_group.get("RegionId") == ecs_security_group.region_id and
                            redis_security_group.get("SecurityGroupId") == ecs_security_group.security_group_id):
                        logger.info(ProcessReport.get_arrow_line(yes=True))
                        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
                        whitelist_check.success()
                        whitelist_check.set_detail(WhitelistNotification.same_security_group_success_detail())
                        return
            private_white_ips = []
            for private_ip in client.private_ips:
                for white_ip in self.ip_whitelist:
                    if utils.is_ip_in_cidr(private_ip, white_ip):
                        private_white_ips.append(private_ip)
                        break

            if len(private_white_ips) > 0:
                if len(client.private_ips) != len(private_white_ips):
                    logger.warning(ProcessReport.get_arrow_line(yes=True, message="unknown"))
                    logger.warning(ProcessReport.step_indentation + ProcessReport.arrow_head)
                    whitelist_check.unknown()
                    whitelist_check.set_detail(WhitelistNotification.private_ip_success_detail(True).format(
                                                ",".join(private_white_ips)))
                else:
                    logger.info(ProcessReport.get_arrow_line(yes=True))
                    logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
                    whitelist_check.success()
                    whitelist_check.set_detail(WhitelistNotification.private_ip_success_detail(False).
                                               format(",".join(private_white_ips)))
                return
            else:
                logger.error(ProcessReport.get_arrow_line(yes=False))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                whitelist_check.fail()
                whitelist_check.set_detail(WhitelistNotification.private_ip_fail_detail().format(
                                            ",".join(client.private_ips)))
                ConnectionDiagnosticReport.add_issue(WhitelistNotification.fail_issue())
                raise WhiteListError(",".join(client.private_ips))

        # Connect via public address, check ip whitelist
        public_white_ips = []
        for public_ip in client.public_ips:
            for white_ip in self.ip_whitelist:
                if utils.is_ip_in_cidr(public_ip, white_ip):
                    public_white_ips.append(public_ip)
                    break
        if len(public_white_ips) > 0:
            if len(client.public_ips) != len(public_white_ips):
                logger.warning(ProcessReport.get_arrow_line(yes=True, message="unknown"))
                logger.warning(ProcessReport.step_indentation + ProcessReport.arrow_head)
                whitelist_check.unknown()
                whitelist_check.set_detail(WhitelistNotification.public_ip_success_detail(True).format(",".join(public_white_ips)))
            else:
                logger.info(ProcessReport.get_arrow_line(yes=True))
                logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
                whitelist_check.success()
                whitelist_check.set_detail(WhitelistNotification.public_ip_success_detail(False).format(",".join(public_white_ips)))
        else:
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            whitelist_check.fail()
            whitelist_check.set_detail(WhitelistNotification.public_ip_fail_detail().format(",".join(client.public_ips)))
            ConnectionDiagnosticReport.add_issue(WhitelistNotification.fail_issue())
            raise WhiteListError(",".join(client.public_ips))

    def diagnose_instance_status(self):
        if not self.advanced_mode:
            ConnectionDiagnosticReport.add_warning(InstanceStatusNotification.not_check_warning())
            return
        logger.info(ProcessReport.gen_process_rectangle(InstanceStatusNotification.diagnose_log()))
        ConnectionDiagnosticReport.add_check(Check(InstanceStatusNotification.check_name()))
        instance_status_check = ConnectionDiagnosticReport.get_last_check()
        if self.instance_status in ["Creating", "Error", "Released"]:
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            ConnectionDiagnosticReport.add_issue(InstanceStatusNotification.fail_detail().format(self.instance_status))
            instance_status_check.fail()
            instance_status_check.set_detail(InstanceStatusNotification.fail_detail().format(self.instance_status))
            raise InstanceError(InstanceStatusNotification.fail_detail().format(self.instance_status))
        logger.info(ProcessReport.get_arrow_line(yes=True))
        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        instance_status_check.success()
        instance_status_check.set_detail(InstanceStatusNotification.success_detail().format(self.instance_status))

    def detect_servers(self, connection_info: Mapping[str, Any]) -> float:
        redis_client = redis.Redis(**connection_info)

        # Get redis server info
        redis_info: Optional[Mapping[str, Any]] = None
        for _ in range(10):
            try:
                redis_info = redis_client.info()
                break
            except redis.RedisError as e:
                logger.warning(ServerDetectionNotification.info_error().format(e))
        if redis_info is None:
            logger.error(ServerDetectionNotification.info_reached_max_retry_times())
            raise ServerError(ServerDetectionNotification.info_reached_max_retry_times())

        # Get architecture type and connection type
        if self.architecture_type is None:
            if redis_info.get("cluster_enabled") == 1 or redis_info.get("redis_mode") == "cluster":
                self.architecture_type = ArchitectureType.CLUSTER
            elif redis_info.get("redis_mode") == "standalone":
                self.architecture_type = ArchitectureType.STANDARD
            else:
                self.architecture_type = ArchitectureType.RWSPLIT
        if self.architecture_type == ArchitectureType.CLUSTER:
            connection_type = ConnectionType.DIRECT if redis_info.get("redis_mode") is not None else ConnectionType.PROXY
        elif self.architecture_type == ArchitectureType.RWSPLIT:
            connection_type = ConnectionType.PROXY
        else:
            connection_type = ConnectionType.DIRECT

        total_detect_count = 1000
        detection_results = []

        # Detect standalone node
        if self.architecture_type == ArchitectureType.STANDARD:
            self.total_node_count = 1
            detection_result = {"connection_type": connection_type.value, "name": "db0",
                                "total_detect_count": total_detect_count}
            stat_results = self.detect_single_server_by_info_command(redis_client=redis_client,
                                                                     detect_count=total_detect_count,
                                                                     server_name=detection_result.get("name"),
                                                                     command_type="info")
            detection_result["stat_results"] = stat_results
            detection_results.append(detection_result)

        # Detect write node and readonly nodes for read/write split architecture
        if self.architecture_type == ArchitectureType.RWSPLIT:
            self.total_node_count = 1 + redis_info.get("connected_slaves", 0)
            if self.total_node_count <= 1:
                raise ServerError(ServerDetectionNotification.rw_split_node_error())

            detect_count_for_each = total_detect_count // self.total_node_count
            for node_index in range(self.total_node_count):  # master + slaves
                detection_result = {"connection_type": connection_type.value,
                                    "total_detect_count": detect_count_for_each}
                if node_index == 0:  # master node
                    detection_result["name"] = "master"
                    stat_results = self.detect_single_server_by_info_command(redis_client=redis_client,
                                                                             detect_count=detect_count_for_each,
                                                                             command_type="iinfo",
                                                                             server_name=detection_result.get("name"),
                                                                             db_index=0)
                    detection_result["stat_results"] = stat_results
                else:  # slave node
                    detection_result["name"] = f"slave_{node_index - 1}"
                    stat_results = self.detect_single_server_by_info_command(redis_client=redis_client,
                                                                             detect_count=detect_count_for_each,
                                                                             command_type="riinfo",
                                                                             db_index=0,
                                                                             server_name=detection_result.get("name"),
                                                                             slave_index=node_index - 1)
                    detection_result["stat_results"] = stat_results
                detection_results.append(detection_result)

        # Detect cluster nodes directly connected
        if self.architecture_type == ArchitectureType.CLUSTER and connection_type == ConnectionType.DIRECT:
            # get cluster shard info
            redis_cluster = redis.RedisCluster(**connection_info)
            cluster_shards_info = redis_cluster.cluster_nodes()
            shards_connection_info = [shard_info.split(":") for shard_info in cluster_shards_info]
            shard_count = len(shards_connection_info)
            self.total_node_count = shard_count
            if self.total_node_count == 0:
                raise ServerError(ServerDetectionNotification.direct_cluster_node_error())

            # Directly connect to db shard
            connection_info_copy = copy.deepcopy(connection_info)
            connection_info_copy.pop("host")
            connection_info_copy.pop("port")
            detect_count_for_each = total_detect_count // self.total_node_count
            for shard_index, shard_connection_info in enumerate(shards_connection_info):
                detection_result = {"connection_type": connection_type.value, "name": f"shard_{shard_index}",
                                    "total_detect_count": detect_count_for_each}
                host, port = shard_connection_info
                port = int(port)
                redis_client_direct = redis.Redis(host=host, port=port, **connection_info_copy)
                stat_results = self.detect_single_server_by_info_command(redis_client=redis_client_direct,
                                                                         detect_count=detect_count_for_each,
                                                                         command_type="info",
                                                                         server_name=detection_result.get("name"))
                detection_result["stat_results"] = stat_results
                detection_results.append(detection_result)

        # Detect cluster nodes and proxy nodes
        if self.architecture_type == ArchitectureType.CLUSTER and connection_type == ConnectionType.PROXY:
            if redis_info.get("nodecount") is not None:
                self.total_node_count = redis_info.get("nodecount")
            else:
                self.total_node_count = self.get_node_count_for_proxy_cluster_instance(redis_client)
            if self.total_node_count == 0:
                raise ServerError(ServerDetectionNotification.proxy_cluster_node_error())

            detect_count_for_each = total_detect_count // self.total_node_count
            for shard_index in range(self.total_node_count):
                detection_result = {"connection_type": connection_type.value, "name": f"shard_{shard_index}",
                                    "total_detect_count": detect_count_for_each}
                stat_results = self.detect_single_server_by_info_command(redis_client=redis_client,
                                                                         detect_count=detect_count_for_each,
                                                                         command_type="iinfo",
                                                                         db_index=shard_index,
                                                                         server_name=detection_result.get("name"))
                detection_result["stat_results"] = stat_results
                detection_results.append(detection_result)

        self.summary_detection_results(detection_results)

        # Get avg rt
        global_total_success_count = 0
        global_total_rt = 0
        for detect_result in detection_results:
            for key, stat_result in detect_result["stat_results"].items():
                global_total_success_count += stat_result["success_count"]
                global_total_rt += stat_result["total_rt"]
        return global_total_rt / global_total_success_count / 1000 # Global avg rt ms

    def get_node_count_for_proxy_cluster_instance(self, redis_client: redis.Redis) -> int:
        index_left = 0
        index_right = 199
        total_detect_times = 0
        max_detect_times = math.ceil(math.log(index_right)) + 20
        while index_left <= index_right and total_detect_times < max_detect_times:
            index_mid = (index_left + index_right) // 2
            try:
                redis_client.execute_command("iinfo {} server".format(index_mid))
                index_left = index_mid + 1
            except redis.ResponseError as e:
                if str(e) == "no such db node":
                    index_right = index_mid - 1
            except Exception:  # retry
                pass
            total_detect_times += 1
        return index_left

    def detect_single_server_by_info_command(
        self,
        redis_client: Union[redis.Redis, redis.RedisCluster],
        detect_count: int,
        command_type: str,
        server_name: str,
        **kwargs
    ) -> Mapping[str, Mapping[str, Any]]:
        # Get command and parameters
        enable_proxy = command_type in ["iinfo", "riinfo"]
        command = "info server"  # default command
        if command_type == "iinfo":  # proxy command for db server
            db_index = kwargs.get("db_index")
            if db_index is None:
                raise InternalError(ServerDetectionNotification.iinfo_parameter_error())
            command = f"iinfo {db_index} server"
        elif command_type == "riinfo":  # proxy command for readonly slave server
            db_index = kwargs.get("db_index")
            slave_index = kwargs.get("slave_index")
            if db_index is None or slave_index is None:
                raise InternalError(ServerDetectionNotification.riinfo_parameter_error())
            command = f"riinfo {db_index} {slave_index} server"

        # Execute command and get statistical results
        stat_results = {}
        stat_result_template = {"success_count": 0, "max_rt": 0, "min_rt": 1e9, "total_rt": 0,
                                "rt_distribution": [0] * 12}
        for _ in tqdm(range(detect_count), server_name):
            try:
                # Execute command
                start = time.time()
                response = redis_client.execute_command(command)
                end = time.time()
            except redis.RedisError:
                continue
            if response is None:
                continue
            # Get access path identifier
            if not enable_proxy:  # No proxy run id
                key = "db"
            else:
                if isinstance(response, bytes):
                    response = response.decode()
                response = {line.split(":")[0]: line.split(":")[1] for line in response.split("\r\n") if
                            len(line.split(":")) >= 2}
                if response.get("proxy_run_id") is None or response.get("proxy_run_id") == "placeholder":
                    key = "db"
                else:
                    key = "proxy_run_id:" + response.get("proxy_run_id")

            if key not in stat_results:
                stat_result = copy.deepcopy(stat_result_template)
                stat_results[key] = stat_result
            else:
                stat_result = stat_results[key]

            # Get statistical results
            rt_us = max((end - start) * 1e6, 1)
            # rt bucket: <256us <512us <1ms <2ms <4ms <8ms <16ms <32ms <64ms <128ms <256ms <max
            if rt_us < 1000:
                index = max(math.ceil(math.log(rt_us, 2)) - 8, 0)
            else:
                index = min(math.ceil(math.log(rt_us / 1000, 2)), 9) + 2
            stat_result["success_count"] += 1
            stat_result["max_rt"] = max(stat_result["max_rt"], rt_us)
            stat_result["min_rt"] = min(stat_result["min_rt"], rt_us)
            stat_result["total_rt"] += rt_us
            stat_result["rt_distribution"][index] += 1

        return stat_results  # Empty if the server is down

    def summary_detection_results(self, detection_results: List[Mapping[str, Any]]):
        if len(detection_results) == 0:
            logger.error(ServerDetectionNotification.no_detect_results_error())
            return

        if self.architecture_type == ArchitectureType.RWSPLIT:
            ServerDiagnosticReport.set_architecture("Read/Write Split")
        else:
            ServerDiagnosticReport.set_architecture(self.architecture_type.value)
        ServerDiagnosticReport.set_connection_type(detection_results[0].get("connection_type"))
        ServerDiagnosticReport.set_node_count(self.total_node_count)

        proxy_id_dict = {}
        for detection_result in detection_results:
            server_name = detection_result.get("name")
            stat_results = detection_result.get("stat_results")
            total_detect_count = detection_result.get("total_detect_count")

            # No statistical result
            if len(stat_results.keys()) == 0:
                ServerDiagnosticReport.add_error_hint(ServerDetectionNotification.server_down_hint().format(server_name))
                continue

            # Not proxy mode or proxy run id is not supported, do not detect the path from proxy to db server
            if stat_results.get("db") is not None and len(stat_results.keys()) == 1:
                result = stat_results.get("db")
                rt_distribution = copy.deepcopy(result["rt_distribution"])
                count = 0
                for i in range(0, len(rt_distribution)):
                    rt_distribution[i] += count
                    count = rt_distribution[i]
                    rt_distribution[i] /= result["success_count"]
                audit_item = AuditItem(server_name, result["success_count"],
                                       result["total_rt"] // result["success_count"],
                                       result["max_rt"], result["min_rt"], rt_distribution)
                ServerDiagnosticReport.add_audit_item(audit_item)
                if total_detect_count > result["success_count"]:
                    ServerDiagnosticReport.add_error_hint(ServerDetectionNotification.server_fail_hint().format(
                        server_name, total_detect_count, total_detect_count - result["success_count"]))
                continue

            # proxy_run_id is supported, need to detect the path from proxy to db server
            total_success_count = 0
            for key, result in stat_results.items():
                if not key.startswith("proxy_run_id:"):
                    logger.error(ServerDetectionNotification.proxy_runid_not_found_error())
                    continue
                total_success_count += result["success_count"]
                proxy_run_id = key.split(":")[1]
                if proxy_id_dict.get(proxy_run_id) is None:
                    proxy_id_dict[proxy_run_id] = len(proxy_id_dict.keys())

                rt_distribution = copy.deepcopy(result["rt_distribution"])
                count = 0
                for i in range(len(rt_distribution)):
                    rt_distribution[i] += count
                    count = rt_distribution[i]
                    rt_distribution[i] /= result["success_count"]
                audit_item = AuditItem(f"proxy{proxy_id_dict[proxy_run_id]}-{server_name}",
                                       result["success_count"], result["total_rt"] // result["success_count"],
                                       result["max_rt"], result["min_rt"], rt_distribution)
                ServerDiagnosticReport.add_audit_item(audit_item)
                if total_success_count < total_detect_count:
                    ServerDiagnosticReport.add_error_hint(ServerDetectionNotification.server_fail_hint().format(
                        server_name, total_detect_count, total_detect_count - total_success_count))
        if len(proxy_id_dict) > 0:
            ServerDiagnosticReport.set_proxy_run_id_info(proxy_id_dict)
