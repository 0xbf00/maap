import abc
import enum
import os
import sys

from termcolor import colored
from typing import Iterator, List

from appxtractor import folder_for_app, SignalIntelligence
from bundle.bundle import Bundle
from misc.logger import create_logger


class Selection(str, enum.Enum):
    ALL = "all"
    MAS = "mas"

    @classmethod
    def choices(cls) -> List[str]:
        return [x.value for x in cls]


class Result(str, enum.Enum):
    OK = " ok "
    ERROR = "err "
    SKIPPED = "skip"

    @property
    def color(self) -> str:
        if self == Result.OK:
            return 'green'
        elif self == Result.ERROR:
            return 'red'
        elif self == Result.SKIPPED:
            return 'yellow'
        else:
            assert False, f"Unhandled case: {self}"

    @property
    def colored(self) -> str:
        return colored(self.value, self.color)


class Driver(abc.ABC):

    def __init__(self, name: str) -> None:
        self.name = name
        self.logger = create_logger(name)

    def run(
        self,
        apps_dir: str,
        out_dir: str,
        select: Selection = Selection.ALL,
    ) -> None:
        if not os.path.exists(apps_dir):
            print(f"Directory does not exist: {apps_dir}", file=sys.stderr)
            exit(1)

        exit_watcher = SignalIntelligence()

        self.logger.info(f"{self.name} starting")

        for app_dir in Driver.iterate_applications(apps_dir):
            if exit_watcher.should_exit:
                break

            app = Bundle.make(app_dir)

            if select == Selection.MAS and not app.is_mas_app():
                continue

            app_out_dir = folder_for_app(out_dir, app)

            os.makedirs(app_out_dir, exist_ok=True)

            print(f"[    ] Analysing {app.filepath}")
            reset_cursor = "\r\033[1A["
            result = self.analyse(app, app_out_dir)
            print(reset_cursor + result.colored)

        self.logger.info(f"{self.name} stopping")

    @abc.abstractmethod
    def analyse(self, app: Bundle, out_dir: str) -> Result:
        raise NotImplementedError

    @staticmethod
    def iterate_applications(directory: str) -> Iterator[str]:
        for root, dirs, files in os.walk(directory):
            if root.endswith('.app'):
                yield root

            app_candidates = [
                os.path.abspath(os.path.join(root, d))
                for d in dirs
                if d.endswith('.app')
            ]

            dirs[:] = [
                d
                for d in dirs
                if not d.endswith('.app')
            ]

            for candidate in app_candidates:
                yield candidate
