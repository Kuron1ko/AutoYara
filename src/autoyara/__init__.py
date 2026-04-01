import os

# Allow importing root-level packages as autoyara subpackages, e.g. autoyara.configs
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _project_root not in __path__:
    __path__.append(_project_root)
