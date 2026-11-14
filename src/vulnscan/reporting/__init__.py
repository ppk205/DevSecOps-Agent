"""Tạo báo cáo: JSON, SARIF 2.1.0, HTML và Markdown.

Một bộ tạo duy nhất quản lý mọi định dạng xuất ra để số lượng trạng thái và giới hạn
độ bao phủ không bị sai lệch giữa các định dạng. HTML được render bởi Jinja2 với
tính năng autoescape được bật; nội dung repository được coi là không đáng tin cậy.
"""
