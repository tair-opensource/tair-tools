from typing import List, Optional

from diagnose import utils
from diagnose.notification_template import NotificationTemplate
from diagnose.exceptions import InternalError
from diagnose.logger_config import logger

BANNER = """
    ____           ___         ____  _                                 
   / __ \___  ____/ (_)____   / __ \(_)___ _____ _____  ____  ________ 
  / /_/ / _ \/ __  / / ___/  / / / / / __ `/ __ `/ __ \/ __ \/ ___/ _ \\
 / _, _/  __/ /_/ / (__  )  / /_/ / / /_/ / /_/ / / / / /_/ (__  )  __/
/_/ |_|\___/\__,_/_/____/  /_____/_/\__,_/\__, /_/ /_/\____/____/\___/ 
                                         /____/                        
"""


class ProcessReport:
    """
        Record the tasks the tool is performing and print a flow chart
    """
    line_width = 70
    title_line = "=" * line_width
    split_line = "-" * line_width

    title_en = utils.center_text("Diagnostic Process", line_width)
    title_zh = utils.center_text("诊断流程", line_width)
    title_end_en = utils.center_text("Diagnosis Complete", line_width)
    title_end_zh = utils.center_text("诊断完成", line_width)

    task_name_width = 35
    tasks_name_en = ["1. Diagnosis Initialization",
                     "2. Detect Connection",
                     "3. AUTH Username And Password",
                     "4. Detect Redis Server"]
    tasks_name_en = [utils.fill_text(task, 35) for task in tasks_name_en]
    tasks_name_zh = ["1. 诊断初始化",
                     "2. 连通性检测",
                     "3. 用户名密码认证",
                     "4. 探测 Redis server"]
    tasks_name_zh = [utils.fill_text(task, 35) for task in tasks_name_zh]

    step_indentation = " " * task_name_width
    steps_zh = {
        "advanced_init": "高级模式初始化",
        "basic_init": "基础模式初始化",
        "tcp_connection": "建立 TCP 连接",
        "auth": "AUTH 用户名和密码",
        "detect_server": "探查 Redis server"
    }
    steps_en = {
        "advanced_init": "Advanced mode initialization",
        "basic_init": "Basic mode initialization",
        "tcp_connection": "Establish a TCP connection",
        "auth": "AUTH username and password",
        "detect_server": "Detect Redis server"
    }

    finish = "结束" if NotificationTemplate.language == "zh" else "Finish"

    rectangle_length = 20
    rectangle_hline = "+" + "-" * (rectangle_length - 2) + "+"
    rectangle_vline = "|"

    arrow_head = " " * (rectangle_length // 2) + "v"
    arrow_line = " " * (rectangle_length // 2) + "| {}"

    @classmethod
    def title(cls) -> str:
        if NotificationTemplate.language == "zh":
            return cls.title_zh
        return cls.title_en

    @classmethod
    def title_end(cls) -> str:
        if NotificationTemplate.language == "zh":
            return cls.title_end_zh
        return cls.title_end_en

    @classmethod
    def get_task_name(cls, index: int) -> str:
        if index < 0 or index >= len(cls.tasks_name_zh):
            raise InternalError("Task name index out of range")
        if NotificationTemplate.language == "zh":
            return cls.tasks_name_zh[index]
        return cls.tasks_name_en[index]

    @classmethod
    def get_step_name(cls, key: str) -> str:
        if NotificationTemplate.language == "zh":
            step_name = cls.steps_zh.get(key)
        else:
            step_name = cls.steps_en.get(key)
        if step_name is None:
            raise InternalError("Step name not found")
        return step_name

    @classmethod
    def gen_process_rectangle(cls, title: str ) -> str:
        rectangle = cls.step_indentation + cls.rectangle_hline + "\n"
        if utils.calculate_text_width(title) <= cls.rectangle_length - 2:
            rectangle += (cls.step_indentation + "|{}|\n".format(utils.center_text(title, cls.rectangle_length - 2)))
        else:
            if NotificationTemplate.language == "zh":
                truncated_titles = utils.split_text_to_fixed_width(title, cls.rectangle_length - 2)
            else:
                truncated_titles = utils.split_text_to_fixed_width_without_word_break(title, cls.rectangle_length - 2)
            for truncated_title in truncated_titles:
                rectangle += (cls.step_indentation + "|{}|\n".format(truncated_title))
        rectangle += (cls.step_indentation + cls.rectangle_hline)
        return rectangle

    @classmethod
    def get_arrow_line(cls, yes: bool, message: str = None):
        arrow_line = cls.step_indentation + cls.arrow_line.format("Yes" if yes else "No")
        return arrow_line + " (" + message + ")" if message is not None else arrow_line


class ConnectionDiagnosticReport:
    """
        Detailed diagnostic report including system information, checks performed, possible problems and warnings
    """
    report_name_en = "Redis Connection Diagnostic Report"
    report_name_zh = "Redis 连接诊断报告"
    client_info = None
    checks = []
    issues = []
    warnings = []
    width = 120
    line = "=" * width

    @classmethod
    def add_check(cls, check: "Check"):
        cls.checks.append(check)

    @classmethod
    def add_issue(cls, issue: str):
        cls.issues.append(issue)

    @classmethod
    def add_warning(cls, warning: str):
        cls.warnings.append(warning)

    @classmethod
    def get_client_info(cls) -> str:
        if cls.client_info is not None:
            return str(cls.client_info)
        else:
            return ""

    @classmethod
    def set_client_info(cls, client_info: "ClientInfo"):
        cls.client_info = client_info

    @classmethod
    def get_last_check(cls) -> Optional["Check"]:
        if len(cls.checks) == 0:
            return None
        return cls.checks[-1]

    @classmethod
    def get_issues(cls) -> str:
        output = ""
        for i in range(1, len(cls.issues) + 1):
            output += f"{i}. {cls.issues[i - 1]}\n"
        return output[:-1]

    @classmethod
    def output_report(cls):
        report_name = cls.report_name_zh if NotificationTemplate.language == "zh" else cls.report_name_en
        system_info_title = "系统信息：" if NotificationTemplate.language == "zh" else "System Information:"
        checks_title = "执行过的检查：" if NotificationTemplate.language == "zh" else "Checks Performed:"
        problem_title = "可能的问题：" if NotificationTemplate.language == "zh" else "Possible Issues:"
        warning_title = "警告：" if NotificationTemplate.language == "zh" else "Warnings:"
        report_head = (f"\n{cls.line}\n{report_name.center(cls.width)}\n{cls.line}\n"
                       f"{system_info_title}\n{repr(cls.client_info)}\n{cls.line}\n"
                       f"{checks_title}\n{cls.line}")
        logger.info(report_head)
        for i in range(len(cls.checks)):
            if cls.checks[i].status == "Success":
                logger.info(f"{i + 1}. {repr(cls.checks[i])}")
            elif cls.checks[i].status == "Failure":
                logger.error(f"{i + 1}. {repr(cls.checks[i])}")
            else:
                logger.warning(f"{i + 1}. {repr(cls.checks[i])}")
        if len(cls.checks) == 0:
            logger.info("(empty)")
        logger.info(f"{cls.line}\n{problem_title}\n{cls.line}")
        for i in range(len(cls.issues)):
            logger.error(utils.wrap_text_by_line_width(f"{i + 1}. {cls.issues[i]}", cls.width))
        if len(cls.issues) == 0:
            logger.info("(empty)")
        logger.info(f"{cls.line}\n{warning_title}\n{cls.line}")
        for i in range(len(cls.warnings)):
            logger.warning(utils.wrap_text_by_line_width(f"{i + 1}. {cls.warnings[i]}", cls.width))
        if len(cls.warnings) == 0:
            logger.info("(empty)")
        logger.info(f"{cls.line}")


class ClientInfo:
    def __init__(self, system: str, public_ips: List[str], private_ips: List[str]):
        self._system = system
        self._public_ips = public_ips
        self._private_ips = private_ips

    def __repr__(self) -> str:
        if NotificationTemplate.language == "zh":
            return f"\t系统: {self._system}\n\t公网 IP: {self._public_ips}\n\t私网 IP: {self._private_ips}"
        return f"\tSystem: {self._system}\n\tPublic IP: {self._public_ips}\n\tPrivate IP: {self._private_ips}"


class Check:
    status_dict = {"Success": "成功", "Failure": "失败", "Unknown": "未知"}

    def __init__(self, name: str, status: str = "Unknown", detail: str = None):
        self._name = name
        self._status = status
        self._detail = detail

    @property
    def status(self):
        return self._status

    def success(self):  # Successfully pass the check
        self._status = "Success"

    def fail(self):  # Fail to pass the check
        self._status = "Failure"

    def unknown(self):  # Unknown check result
        self._status = "Unknown"

    @property
    def detail(self):
        return self._detail

    def set_detail(self, detail: str):
        self._detail = detail

    def __repr__(self):
        if NotificationTemplate.language == "zh":
            repr_str = f"{self._name}\n   -状态： [{Check.status_dict.get(self._status)}]"
        else:
            repr_str = f"{self._name}\n   -Status: [{self._status}]"
        if self.detail is not None:
            repr_str += "\n"
            detail_title = "详情：" if NotificationTemplate.language == "zh" else "Details:"
            repr_str += utils.wrap_text_by_line_width(f"   -{detail_title} {self._detail}", ConnectionDiagnosticReport.width)
        return repr_str


class ServerDiagnosticReport:
    """
        Redis Server Diagnostic Report, including architecture information, and the rt of server response
    """
    architecture_dict = {"Read/Write Split": "读写分离架构", "cluster": "集群架构", "standard": "标准架构"}
    connection_type_dict = {"proxy": "代理", "direct": "直连"}
    report_name_en = "Redis Server Diagnostic Report"
    report_name_zh = "Redis Server 诊断报告"
    width = 166
    line = "-" * width

    # server info
    architecture = None
    connection_type = None
    node_count = 0
    proxy_run_id_2_node_index = None

    # audit info
    titles = ["path".center(15), "success count".center(13), "avg rtt (ms)".center(12), "max rtt (ms)".center(12),
              "min rtt (ms)".center(12), "<256us".center(7), "<512us".center(7), "<1ms".center(7), "<2ms".center(7),
              "<4ms".center(7), "<8ms".center(7), "<16ms".center(7), "<32ms".center(7), "<64ms".center(7),
              "<128ms".center(7), "<256ms".center(7), "<max".center(7)]
    audit_items = []

    # error hints
    error_hints = []

    @classmethod
    def set_architecture(cls, architecture: str):
        cls.architecture = architecture

    @classmethod
    def set_connection_type(cls, connection_type: str):
        cls.connection_type = connection_type

    @classmethod
    def set_node_count(cls, node_count: int):
        cls.node_count = node_count

    @classmethod
    def add_audit_item(cls, audit_item: "AuditItem"):
        cls.audit_items.append(audit_item)

    @classmethod
    def add_error_hint(cls, error_hint: str):
        cls.error_hints.append(error_hint)

    @classmethod
    def set_proxy_run_id_info(cls, proxy_run_id_2_node_index: dict):
        cls.proxy_run_id_2_node_index = proxy_run_id_2_node_index

    @classmethod
    def generate_report(cls) -> str:
        report_name = cls.report_name_zh if NotificationTemplate.language == "zh" else cls.report_name_en
        architecture_title = "架构：" if NotificationTemplate.language == "zh" else "Architecture: "
        connection_type_title = "连接类型：" if NotificationTemplate.language == "zh" else "Connection type: "
        node_count_title = "节点总数：" if NotificationTemplate.language == "zh" else "Total node count: "
        if NotificationTemplate.language == "zh":
            architecture = cls.architecture_dict.get(cls.architecture)
            connection_type = cls.connection_type_dict.get(cls.connection_type)
        else:
            architecture = cls.architecture
            connection_type = cls.connection_type
        report = f"\n{cls.line}\n{report_name.center(cls.width)}\n{cls.line}\n"
        report += f"{architecture_title}{architecture}\n"
        report += f"{connection_type_title}{connection_type}\n"
        if cls.architecture is not None and "split" in cls.architecture.lower():
            report += f"{node_count_title}{cls.node_count} (1 master + {cls.node_count - 1} slaves)\n"
        else:
            report += f"{node_count_title}{cls.node_count}\n"
        if cls.proxy_run_id_2_node_index is not None:
            proxy_info_title = "代理节点run id 和节点索引映射：" if NotificationTemplate.language == "zh" else \
                "Proxy node run id and node index mapping: "
            report += f"{proxy_info_title}{cls.proxy_run_id_2_node_index}\n"
        report += f"{cls.line}\n|"
        for title_item in cls.titles:
            report = report + title_item + "|"
        report += "\n"
        for audit_item in cls.audit_items:
            report += repr(audit_item)
        report += cls.line
        report += "\n"
        if len(cls.error_hints) > 0:
            for error_hint in cls.error_hints:
                report += utils.wrap_text_by_line_width(error_hint, cls.width)
                report += "\n"
            report += cls.line
            report += "\n"
        return report


class AuditItem:
    def __init__(
        self,
        path: str,
        success_count: int,
        avg_rtt: int,
        max_rtt: int,
        min_rtt: int,
        rtt_distribution: List[float]
    ):
        self.path = path
        self.success_count = success_count
        self.avg_rtt = avg_rtt / 1000
        self.max_rtt = max_rtt / 1000
        self.min_rtt = min_rtt / 1000
        self.rtt_formatted_distribution = []
        for rtt in rtt_distribution:
            self.rtt_formatted_distribution.append(f"{rtt * 100:.2f}%")

    def __repr__(self) -> str:
        formated_avg_rtt = f"{self.avg_rtt:.3f}"
        formated_max_rtt = f"{self.max_rtt:.3f}"
        formated_min_rtt = f"{self.min_rtt:.3f}"

        repr_str = (f"|{self.path.center(15)}|{str(self.success_count).center(13)}|{formated_avg_rtt.center(12)}|"
                    f"{formated_max_rtt.center(12)}|{formated_min_rtt.center(12)}")
        for rtt in self.rtt_formatted_distribution:
            repr_str += f"|{rtt.center(7)}"
        return repr_str + "|\n"
