from datetime import date, datetime as dt, timedelta, timezone
from zoneinfo import ZoneInfo

naive = dt.now()
legacy = dt.utcnow()
local = dt.fromtimestamp(epoch)
next_run = value + timedelta(days=1)
calendar_today = dt.today()
factory = dt.utcnow

safe_instant = dt.fromtimestamp(epoch, timezone.utc)
safe_date = date.today() + timedelta(days=1)
safe_zone = dt.now(tz=ZoneInfo("America/New_York")) + timedelta(days=1)
