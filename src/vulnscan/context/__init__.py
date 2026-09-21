"""Source context indexing: Java servlets, filters, JSP mapping."""

from .source_index import build_source_index
from .jsp_mapping import index_jsp_files

__all__ = ["build_source_index", "index_jsp_files"]
