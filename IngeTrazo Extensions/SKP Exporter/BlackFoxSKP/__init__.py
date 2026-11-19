from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

_spec = spec_from_file_location(
    __name__ + "._exporter", Path(__file__).with_name("BlackFox_SKP_EXPORTER_1.0.0.py")
)
_exporter = module_from_spec(_spec)
sys.modules[_spec.name] = _exporter
try:
    _spec.loader.exec_module(_exporter)
except BaseException:
    sys.modules.pop(_spec.name, None)
    raise

setup = _exporter.setup
__version__ = _exporter.__version__
