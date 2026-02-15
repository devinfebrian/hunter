"""Hunter Agents Module"""

from .base import BaseAgent
from .sqli import SQLiAgent
from .xss import XSSAgent

__all__ = ["BaseAgent", "SQLiAgent", "XSSAgent"]
