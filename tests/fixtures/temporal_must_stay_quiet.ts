const amount = spending.toLocaleString("en-US", { style: "currency", currency: "USD" });
const count = attendees.length.toLocaleString();
const labels = created.toLocaleDateString("en-US", { timeZone: displayZone });
const localZone = created.toLocaleDateString("en-US", timeZone && { timeZone });
const systemZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const text = "created.toLocaleDateString() and new Date(\"2026-03-08\")";
const embedded = `${new Date("2026-03-08")}`;
