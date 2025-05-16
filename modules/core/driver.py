from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class DriverResult:
    """
    Encapsulates the raw output information returned by a tool run.

    Attributes:
        raw_output: Path or identifier of the raw output file (e.g., XML, JSON).
        metadata: Optional dictionary for extra details (e.g., return code).
    """
    raw_output: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ParsedResult:
    """
    Holds structured data extracted from a raw tool output.

    Attributes:
        data: Parsed, tool-independent dictionary.
        metadata: Optional dictionary for parser-specific info.
    """
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class BaseToolDriver(ABC):
    """
    Abstract base class for all tool drivers.

    Enforces a consistent interface: every driver must implement `run()` and `parse()`.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        session_mgr: Any,
        logger: Any,
    ):
        self.config = config
        self.session_mgr = session_mgr
        self.logger = logger

    @abstractmethod
    def run(self, target: str, **kwargs) -> DriverResult:
        """
        Execute the tool against a given target.

        Returns a DriverResult pointing to raw output files.
        """
        pass

    @abstractmethod
    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Parse raw output from the tool into structured data.

        Returns a ParsedResult with the extracted data.
        """
        pass
