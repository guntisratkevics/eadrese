import datetime as _dt
from dateutil import tz

def tz_riga() -> _dt.tzinfo:
    return tz.gettz("Europe/Riga")
