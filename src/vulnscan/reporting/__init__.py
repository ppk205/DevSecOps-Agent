"""Report generation: JSON, SARIF 2.1.0, HTML, and Markdown.

A single generator owns every exported format so status counts and coverage
limitations cannot drift between them.  HTML is rendered by Jinja2 with
autoescape enabled; repository content is untrusted.
"""
