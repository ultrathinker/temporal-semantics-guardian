from datetime import datetime as dt
from datetime import date, timedelta, timezone
from zoneinfo import ZoneInfo

naive = dt.now()
legacy = dt.utcnow()
local = dt.fromtimestamp(epoch)
next_run = value + timedelta(days=1)

safe_instant = dt.fromtimestamp(epoch, timezone.utc)
safe_date = date.today() + timedelta(days=1)
safe_zone = dt.now(tz=ZoneInfo("America/New_York")) + timedelta(days=1)
