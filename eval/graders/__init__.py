from eval.graders.containment import grade as _containment
from eval.graders.coordination import grade as _coordination
from eval.graders.injection import grade as _injection
from eval.graders.overblock import grade as _overblock
from eval.graders.security_spoofing import grade as _security_spoofing
from eval.graders.utility import grade as _utility

GRADERS = {
    "security_spoofing": _security_spoofing,
    "injection": _injection,
    "overblock": _overblock,
    "utility": _utility,
    "coordination": _coordination,
    "containment": _containment,
}
