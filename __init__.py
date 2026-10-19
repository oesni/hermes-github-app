"""Hermes directory plugin entrypoint."""
if __package__:
    from .hermes_github_app.plugin import register
    __all__ = ['register']
else:
    __all__ = []
