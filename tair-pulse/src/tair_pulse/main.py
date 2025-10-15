import argparse
import datetime
import itertools
import signal
import threading
import time
from typing import Union
import rich
from rich.console import Console
import plotly.graph_objects as go
import redis
from tair_pulse.keys import SLOT2KEY
# Configure rich console with highlight=False
console = Console(highlight=False)

# args
EXAMPLES = """
Examples:

 Run the TairPulse with the default configuration against 127.0.0.1:6379:
   $ tair-pulse

 Test Aliyun Tair instance without password:
   $ tair-pulse --host r-bp1qf8wio5zkp01pzt.redis.rds.aliyuncs.com
 Test Cluster instance with password, one of the nodes is 192.168.10.1:7000:
   $ tair-pulse --host 192.168.10.1 --port 7000 --password 123456 --cluster
"""
parser = argparse.ArgumentParser(prog="tair-pulse",
                                 description="TairPulse is a tool to visualize Tair/Redis latency and availability.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=EXAMPLES)
parser.add_argument("--host", default="127.0.0.1", help="server hostname (default 127.0.0.1)")
parser.add_argument("--port", default=6379, help="server port (default 6379)")
parser.add_argument("--password", default="", help="password for Tair/Redis auth")
parser.add_argument("--cluster", default=False, action="store_true", help="server is a node of the Tair/Redis cluster")
parser.add_argument("--max-rt", default=0, type=float, help="print the key that exceeds the max-rt (default 0)")
parser.add_argument("--fork", default=False, action="store_true", help="use `save` to trigger fork(2) in order to test latency")
g_args = parser.parse_args()
if g_args.cluster and g_args.fork:
    parser.error("--fork is not supported for cluster mode")

TYPE_CLIENT = Union[redis.RedisCluster, redis.Redis]

stopped = False
# data
data_dict = {}
# latency
datetime_array = []
latency_array = []
# error
error_dict = {}

TIMEOUT_SECONDS = 3


class ErrorPair:
    def __init__(self):
        self.array = []
        self.start_datetime = None


def slot_order(slot_cnt):
    result = [0]
    shard_cnt = 1
    while len(result) < slot_cnt:
        shard_cnt *= 2
        result = result + [i + slot_cnt // shard_cnt for i in result]
    return result


KEYS = ["tair_pulse_{{{0}}}".format(SLOT2KEY[slot]) for slot in slot_order(16384)]
g_stopped = False
g_error = {}


class LatencySegment:
    def __init__(self):
        self.latency = []

    def add(self, latency):
        self.latency.append(latency)

    def __str__(self):
        length = len(self.latency)

        if length == 0:
            return "0"
        self.latency.sort()
        return "avg: {0:.2f}ms, min: {1:.2f}ms, max: {2:.2f}ms".format(
            sum(self.latency) / length, self.latency[0], self.latency[-1])

    def clear(self):
        self.latency.clear()


def clean_keys():
    try:
        r = create_client()
        for key in KEYS:
            r.delete(key)
        if g_args.fork:
            print("remove 16G data in fork mode")
            for i in range(1024):
                r.delete("tair_pulse_fork_test_{0}".format(i))
    except redis.exceptions.RedisError as e:
        print("error occurred when cleaning up keys: {0}".format(e))
        return


def clear_all_errors():
    for error in error_dict.values():
        if error.start_datetime is not None:
            error.array.append((error.start_datetime, datetime.datetime.now()))
            error.start_datetime = None


def init_database():
    try:
        r = create_client()
        if g_args.fork:
            # add 4G data
            print("start fork test, add 16G data")
            data_size = 16 * 1024 * 1024
            for i in range(1024):
                assert r.set("tair_pulse_fork_test_{0}".format(i), "v" * data_size)

        for inx, key in enumerate(KEYS):
            assert r.set(key, inx)
            data_dict[key] = inx
    except redis.exceptions.RedisError as e:
        print("error occurred when init database: {0}".format(e))
        exit(0)


def run_write_cmd():
    r = create_client()

    log_time = time.time()
    latency_segment = LatencySegment()

    for key in itertools.cycle(KEYS):
        if stopped:
            break

        start_date = datetime.datetime.now()
        error = None

        # latency
        start_time = time.time()
        try:
            ret = r.incr(key)
            data_dict[key] += 1
            assert ret == data_dict[key], "data error: key:{} diff:{}".format(key, ret - data_dict[key])
        except Exception as e:
            error = str(e)
        latency = round((time.time() - start_time) * 1000, 2)
        if g_args.max_rt != 0 and latency > g_args.max_rt:
            print("{0} latency is too high: {1}, key:{2}".format(
                datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3], latency, key))

        # error
        if error is not None:
            if error not in error_dict:
                error_dict[error] = ErrorPair()
            if error_dict[error].start_datetime is None:
                clear_all_errors()
                error_dict[error].start_datetime = start_date
                print("{0} error occurred when writing data: {1}".format(
                    datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3], error))
        else:
            clear_all_errors()

        # log
        latency_segment.add(latency)
        if start_time > log_time:
            log_time = start_time + 5
            print("{0} {1} {2}".format(
                datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3], 
                latency_segment, 
                '' if error is None else 'error'))
            latency_segment.clear()

        datetime_array.append(start_date)
        latency_array.append(round(latency, 2))

    clear_all_errors()


def signal_handler(sig, frame):
    global stopped
    if stopped:
        console.print("\nYou pressed Ctrl+C twice!", style="red")
        exit(0)
    console.print("\nYou pressed Ctrl+C!", style="red")
    stopped = True


def create_client(timeout=TIMEOUT_SECONDS) -> TYPE_CLIENT:
    if g_args.fork:
        timeout = 60  # 60s for fork test

    if g_args.cluster:
        r = redis.RedisCluster(host=g_args.host, port=g_args.port, password=g_args.password,
                               cluster_error_retry_attempts=0,
                               socket_timeout=timeout,
                               socket_connect_timeout=timeout,
                               retry_on_timeout=False,
                               retry=None,
                               single_connection_client=True)

    else:
        r = redis.Redis(host=g_args.host, port=g_args.port, password=g_args.password,
                        socket_timeout=timeout,
                        socket_connect_timeout=timeout,
                        retry_on_timeout=False,
                        retry=None,
                        single_connection_client=True)
    return r


def dbsize() -> int:
    try:
        total_size = 0
        r = create_client()
        if g_args.cluster:
            redis_nodes = r.cluster_nodes()
            for node in redis_nodes:
                host, port = node.split(":")
                node_conn = redis.Redis(host=host, port=port, password=g_args.password)
                node_conn_size = node_conn.dbsize()
                total_size += node_conn_size
        else:
            total_size = r.dbsize()
    except redis.exceptions.RedisError as e:
        print("error occurred when get dbsize: {0}".format(e))
        return 0
    return total_size


def save_command():
    time.sleep(5)
    while not stopped:
        try:
            r = create_client()
            assert r.execute_command("bgsave")
            time.sleep(10)  # add interval 10s
        except redis.exceptions.RedisError as e:
            if "in progress" in str(e):
                time.sleep(0.5)
                continue
            print("error occurred when save: {0}".format(e))


def main():
    filename = "pulse_{0}.html".format(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M'))
    signal.signal(signal.SIGINT, signal_handler)

    console.print("[green]1. init database[/green]")
    init_database()

    if g_args.fork:
        print("start `save` thread...")
        thread = threading.Thread(target=save_command)
        thread.start()

    old_dbsize = dbsize()
    console.print("[green]2. start latency test[/green]")
    run_write_cmd()

    console.print("[green]3. reset database[/green]")
    clean_keys()
    now_dbsize = dbsize()

    print("Write data to latency.html... {0}".format(len(datetime_array)))
    from plotly_resampler import FigureResampler
    from plotly.subplots import make_subplots

    # Calculate dynamic spacing and height based on number of errors
    error_count = len(error_dict)
    # Base spacing: 0.15 when no errors, each error item adds about 25px spacing
    # Additional spacing: error_count * 25px / 800px
    vertical_spacing = 0.15 + (error_count * 25 / 800)
    vertical_spacing = min(vertical_spacing, 0.5)  # Cap at 0.5 to avoid too much space
    
    # Adjust total height based on error count: base 800px + error_count * 30px
    total_height = 800 + error_count * 30
    total_height = min(total_height, 1500)  # Cap at 1500px

    # Create figure with 2 subplots stacked vertically
    fig = make_subplots(rows=2, cols=1,
                        subplot_titles=("Latency Over Time", "Latency Histogram"),
                        vertical_spacing=vertical_spacing,
                        specs=[
                            [{"type": "scatter"}],
                            [{"type": "scatter"}]  # Changed from histogram to scatter
                        ],
                        y_title="Latency (ms)")  # Add y-axis title for all subplots

    # Add the first subplot (latency over time)
    resampler = FigureResampler(fig, default_n_shown_samples=10000)

    # Change back to original line chart (Scattergl) for better performance
    resampler.add_trace(
        go.Scattergl(
            name='latency',
            showlegend=False,
            line=dict(width=1, color='blue'),
            hovertemplate='date: %{x|%Y-%m-%d %H:%M:%S.%L}<br>latency: %{y:.3f}ms<extra></extra>'
        ),
        hf_x=datetime_array,
        hf_y=latency_array,
        row=1, col=1
    )

    max_y = max(latency_array) if latency_array else 0
    total_width = 0
    for error_name, error in error_dict.items():
        x = [i[0] for i in error.array]
        y = [max_y for _ in error.array]
        width = [(i[1] - i[0]).total_seconds() * 1000 for i in error.array]
        total_width += sum(width)
        name = "{0}  --  {1} times, {2:.3f}s".format(error_name, len(error.array), sum(width) / 1000)
        resampler.add_trace(go.Bar(x=x, y=y, width=width, offset=0, name=name, opacity=0.7), row=1, col=1)

    # Sort latencies for percentile calculation
    latency_array.sort()

    percentiles = []
    percentile_values = []

    for inx, lat in enumerate(latency_array):
        percentiles.append(inx / len(latency_array) * 100)
        percentile_values.append(lat)

    # Add percentile line chart
    resampler.add_trace(
        go.Scatter(
            line=dict(color='green', width=1),
            showlegend=False,  # Remove legend as requested
            hovertemplate='percentile: %{x:.4f}%<br>latency: %{y:.3f}ms<extra></extra>'
        ),
        hf_x=percentiles,
        hf_y=percentile_values,
        row=2, col=1
    )

    # Update layout
    resampler.update_layout(
        title="tair-pulse ({0}:{1})".format(g_args.host, g_args.port),
        height=total_height,  # Dynamic height based on error count
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=0.01,
            bgcolor="rgba(255, 255, 255, 0.9)",
            bordercolor="rgba(0, 0, 0, 0.3)",
            borderwidth=1
        ),
        bargap=0,  # Remove gaps between bars in the first subplot
        bargroupgap=0  # Remove gaps between bar groups
    )

    resampler.write_html(filename)
    resampler.show_dash(mode="external")

if __name__ == "__main__":
    main()
