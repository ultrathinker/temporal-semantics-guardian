const birthday = new Date("2026-03-08");
const local = new Date("2026-03-08 10:00");
const reportDay = createdAt
  .toISOString()
  .split("T")[0];
const dayMilliseconds = 1000 * 60 * 60 * 24;
const reportLabel = createdAt.toLocaleDateString(locale);

const amount = total.toLocaleString("en-US", {
  style: "currency",
  currency: "USD"
});
const zonedLabel = createdAt.toLocaleDateString(locale, {
  timeZone: displayZone
});
const explicitInstant = new Date("2026-03-08T10:00:00Z");
