# Retired: custom pfSense decoder/rule

This folder documents work that was built, debugged, and fully functional -
then deliberately retired, not abandoned or failed.

## What happened

pfSense was configured to forward its firewall logs to Wazuh over syslog.
At the time, no built-in Wazuh support for pfSense's log format was known
about, so a custom decoder and rule pair (local IDs 100020/100021) were
hand-written to parse pfSense's raw `filterlog` CSV format and promote
block/pass events to Wazuh alerts.

Building it surfaced two real bugs, both diagnosed and fixed:
- A field named `action` collided with a Wazuh-reserved field name and had
  to be renamed.
- A regex written assuming every field would contain something broke the
  moment it hit a real log line with a legitimately empty field.

## Why it was retired

Once the syslog pipe and the corrected regex were both verified working,
testing against a live pfSense block event showed the alert that actually
fired wasn't the custom rule at all - it was Wazuh's own **built-in native
pfSense decoder/rule (rule 87701)**, which had been parsing the same syslog
stream in parallel the whole time, independent of the custom work.

Since the built-in rule was verified against this lab's real traffic and
covers the same events correctly, the custom decoder/rule pair was retired
rather than kept as redundant, unused code alongside it.

## Why this is kept in the repo at all

Checking for existing vendor/built-in coverage before writing custom
detection is a real, practical SOC habit - this is the concrete record of
that check actually happening, not just the clean end result.
