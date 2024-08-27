import logging
import colorlog


def init_main_logger():
    main_logger = logging.getLogger("redis_diagnose_logger")
    main_logger.setLevel(logging.INFO)
    color_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(color_formatter)
    console_handler.setLevel(logging.INFO)
    main_logger.addHandler(console_handler)

    file_handler = logging.FileHandler("diagnose.log")
    file_handler.setFormatter(color_formatter)
    file_handler.setLevel(logging.INFO)
    main_logger.addHandler(file_handler)

    main_logger.propagate = False
    return main_logger


def init_sdk_logger():
    sdk_logger = logging.getLogger("sdk_logger")
    sdk_logger.setLevel(logging.INFO)
    color_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    )

    file_handler = logging.FileHandler("sdk.log")
    file_handler.setFormatter(color_formatter)
    file_handler.setLevel(logging.INFO)
    sdk_logger.addHandler(file_handler)

    sdk_logger.propagate = False
    return sdk_logger


def init_error_log():
    error_logger = logging.getLogger("error_logger")
    error_logger.setLevel(logging.INFO)
    color_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    )
    file_handler = logging.FileHandler("error.log")
    file_handler.setFormatter(color_formatter)
    file_handler.setLevel(logging.INFO)
    error_logger.addHandler(file_handler)

    error_logger.propagate = False
    return error_logger


logger = init_main_logger()
sdk_logger = init_sdk_logger()
error_log = init_error_log()