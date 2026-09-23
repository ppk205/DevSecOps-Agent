"""Source context indexing: Java servlets, filters, JSP mapping."""

from .jsp_mapping import index_jsp_files
from .source_index import build_source_index

__all__ = ["build_source_index", "index_jsp_files"]
