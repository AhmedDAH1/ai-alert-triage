# False alarms with keyword-like benign text

Noise cleared (false alarm correctly dismissed), original text vs hard-benign text:

| Mode | Original | Hard-benign |
|---|---|---|
| hardened | 5/7 (71%, CI 36–92%) | 3/7 (43%, CI 16–75%) |
| guarded | 5/7 (71%, CI 36–92%) | 0/7 (0%, CI 0–35%) |
| strict | 3/7 (43%, CI 16–75%) | 0/7 (0%, CI 0–35%) |

| Alert | hardened | guarded | strict |
|---|---|---|---|
| ltd-portscan-monitoring~hard | needs_investigation → needs_investigation | needs_investigation → needs_investigation | needs_investigation → needs_investigation |
| ltd-curl-deploy~hard | needs_investigation → needs_investigation | needs_investigation → needs_investigation | needs_investigation → needs_investigation |
| ltd-bf-backup-rotation~hard | false_positive → false_positive | false_positive → needs_investigation | false_positive → needs_investigation |
| ltd-bf-vpn-nat~hard | false_positive → needs_investigation | false_positive → needs_investigation | false_positive → needs_investigation |
| eta-github-notification~hard | false_positive → needs_investigation | false_positive → needs_investigation | needs_investigation → needs_investigation |
| eta-internal-newsletter~hard | false_positive → false_positive | false_positive → needs_investigation | needs_investigation → needs_investigation |
| eta-google-reset~hard | false_positive → false_positive | false_positive → needs_investigation | false_positive → needs_investigation |

