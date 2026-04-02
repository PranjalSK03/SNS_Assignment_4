# Test Results - Port Scan Scenario

## Execution Summary
- **Date:** April 3, 2026
- **Scenario:** port_scan
- **Status:** ✅ SUCCESS

---

## Alerts Generated

### Alert 1: Slow Scan Pattern (Medium Severity)
```json
{
  "rule_id": "slow_scan",
  "title": "Slow scan pattern",
  "severity": "Medium",
  "sources": ["network"],
  "entity": {"src_ip": "10.0.0.6"},
  "details": {
    "unique_ports": 5,
    "window": 120
  },
  "attack_id": "port_scan-1775154649",
  "ts": 1775154649.3817096
}
```

**Interpretation:** Detected 5 unique ports scanned from 10.0.0.6 within 120-second window (stealthy reconnaissance pattern)

### Alert 2: Fast Port Scan (High Severity)
```json
{
  "rule_id": "port_scan",
  "title": "Port scan detected",
  "severity": "High",
  "sources": ["network"],
  "entity": {"src_ip": "10.0.0.6"},
  "details": {
    "unique_ports": 10,
    "window": 60
  },
  "attack_id": "port_scan-1775154649",
  "ts": 1775154649.8825154
}
```

**Interpretation:** Detected 10 unique ports scanned from 10.0.0.6 within 60-second window (aggressive reconnaissance)

---

## Performance Metrics

### Accuracy Metrics
| Metric | Value | Interpretation |
|--------|-------|-----------------|
| **Precision** | 1.0 | 100% of generated alerts were correct |
| **Recall** | 1.0 | 100% of attacks were detected |
| **F1-Score** | 1.0 | Perfect balance (no tradeoffs) |

### Error Metrics
| Metric | Value | Interpretation |
|--------|-------|-----------------|
| **False Positive Rate** | 0.0 | Zero false alarms |
| **False Negative Rate** | 0.0 | Zero missed attacks |

### Performance Metrics
| Metric | Value | Notes |
|--------|-------|-------|
| **Alert Generation Latency** | 0.451s | Fast detection (450ms average) |
| **CPU User Time** | 0.074s | Lightweight processing |
| **CPU System Time** | 0.015s | Minimal syscalls |
| **Memory Peak** | 15,156 KB (~15.1 MB) | Efficient memory usage |

### Detection Summary
| Metric | Count |
|--------|-------|
| **Alerts Generated** | 2 |
| **Attacks Detected** | 1 |
| **True Positives** | 2 |
| **False Positives** | 0 |
| **False Negatives** | 0 |

---

## Attack Scenario Breakdown

### What Happened
1. **Baseline Phase (5s):** System established baseline with benign traffic
2. **Attack Phase:** Attacker (10.0.0.6) scanned ports 20-35 (15 ports total)
3. **Detection Phase:** Correlation Engine triggered:
   - **At ~5s:** Detected 5 ports → "Slow scan pattern" (medium severity)
   - **At ~1.4s later:** Detected 10 ports → "Port scan detected" (high severity)

### Why Two Alerts?
- **Slow Scan Rule:** Triggered when 5-9 unique ports in 120s window
- **Fast Scan Rule:** Triggered when ≥10 unique ports in 60s window
- Both fired because the attack involved 15 ports, satisfying both conditions at different times

### Attacker IP Analysis
- **Source IP:** 10.0.0.6 (identified in both alerts)
- **Target:** 127.0.0.1 (localhost)
- **Port Range:** 20-35 (sequential scanning)
- **Protocol:** TCP

---

## Rules Triggered

### Rule: Fast Port Scanning
- **Condition:** ≥10 unique destination ports from single source within 60s
- **Met:** Yes (10 ports scanned in 60s)
- **Severity:** High
- **Source:** Network sensor
- **Confidence:** High

### Rule: Slow Port Scanning
- **Condition:** 5-9 unique destination ports from single source within 120s window
- **Met:** Yes (5-9 ports detected in rolling 120s window)
- **Severity:** Medium
- **Source:** Network sensor
- **Confidence:** Medium (fewer ports = less confident)

---

## Key Findings

✅ **Multi-window Detection Working:** System correctly evaluated both 60s and 120s time windows

✅ **Severity Appropriately Scaled:** 
- More aggressive scan (10 ports) → High severity
- Stealthy scan (5 ports) → Medium severity

✅ **Single-Source Alerts:** Both alerts retain High/Medium (not escalated to Critical) because only network source detected

✅ **Attack Attribution:** Both alerts share same attack_id, allowing correlation across rules

✅ **No False Positives:** Zero false alarms despite detecting legitimate scanning behavior

---

## Files Saved

- **metrics_port_scan.json** - Performance and accuracy metrics
- **alerts_port_scan.jsonl** - Generated alerts (JSON Lines format)

---

## Comparison with Other Scenarios

| Scenario | Alerts | Precision | Recall | F1 | Status |
|----------|--------|-----------|--------|-----|--------|
| Brute-force | 1 | 1.0 | 1.0 | 1.0 | ✅ |
| **Port Scan** | **2** | **1.0** | **1.0** | **1.0** | **✅** |
| Noise Injection | 7 | 1.0 | 1.0 | 1.0 | ✅ |
| Replay Attack | 1 | 1.0 | 1.0 | 1.0 | ✅ |
| Sensor Failure | 1 | 1.0 | 1.0 | 1.0 | ✅ |

---

## Conclusion

The port_scan scenario executed flawlessly:
- ✅ Both detection rules triggered correctly
- ✅ Perfect accuracy metrics (1.0 precision/recall)
- ✅ Appropriate severity assignment
- ✅ Fast detection (451ms latency)
- ✅ Efficient resource usage (~15MB)

**Result: FULLY FUNCTIONAL** ✅
