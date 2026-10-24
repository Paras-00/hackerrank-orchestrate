# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary

This report presents the comprehensive evaluation results of the AI-powered deletion-audit agent for Northstar Shop. The agent was evaluated against the public sample benchmark (32 requests with verified ground truth) as well as 3 challenging custom edge cases.

## 2. Benchmark Accuracy Metrics

- **Case-Level Deletion-Status Accuracy**: **32/32 (100.0%)**
- **Step Precision**: **86.4%**
- **Step Recall**: **79.3%**
- **Step F1-Score**: **82.7%**
- **Sequence Accuracy**: **59.4%**

### Field-Level Accuracy

| Field Name | Accuracy | Description |
|---|---|---|
| `phase` | 89.7% | Correctness of `phase` assignment across matched steps |
| `system_id` | 89.7% | Correctness of `system_id` assignment across matched steps |
| `resource_id` | 86.7% | Correctness of `resource_id` assignment across matched steps |
| `operation` | 86.7% | Correctness of `operation` assignment across matched steps |
| `state` | 87.7% | Correctness of `state` assignment across matched steps |
| `evidence_id` | 84.1% | Correctness of `evidence_id` assignment across matched steps |

## 3. Custom Evaluation Cases

### custom_case_01: Non-Deletion Account Preference Update

- **Description**: Customer requests to update phone number and explicitly asks to leave the account open.
- **Predicted Status**: `NOT_APPLICABLE`
- **Expected Status**: `NOT_APPLICABLE`
- **Steps Produced**: 0
- **Outcome**: **PASSED**

### custom_case_02: Active Recreation Path with Connector & Backup

- **Description**: User requested deletion, primary account was marked completed, but an active data flow and support tickets remain.
- **Predicted Status**: `INCOMPLETE`
- **Expected Status**: `INCOMPLETE`
- **Steps Produced**: 8
- **Outcome**: **PASSED**

### custom_case_03: Compliant Account Tombstone and Audit Log Retention

- **Description**: User account was deleted, tombstone has all PII redacted, security audit log is properly retained.
- **Predicted Status**: `COMPLETE`
- **Expected Status**: `COMPLETE`
- **Steps Produced**: 3
- **Outcome**: **PASSED**

## 4. Failures Found and Improvements Made

During development and iterative testing against the reference dataset, several subtle failure modes were uncovered and systematically fixed:

1. **Snapshot Bundle Timestamps vs File Manifest Timestamps**:
   - *Failure*: Snapshot bundles (such as `customer_data_snapshot_bundle_20260917.json`) bundle point-in-time snapshots captured on earlier dates (e.g. `2026-09-15`). Using the file manifest export date (`2026-09-17`) improperly disqualified valid evidence from before the case's `audit_at`.
   - *Fix*: The indexer was updated to parse individual snapshot header timestamps (`s.get('captured_at')`), ensuring exact temporal alignment with case audit cutoffs.

2. **Replica SQL Table Scope**:
   - *Failure*: Incomplete SQL parsing missed `customer_data_read_replica` and regional reporting replicas (`customer_data_replica_ap_south`, `customer_data_replica_eu_west`), leading to undetected replication drift.
   - *Fix*: Implemented dynamic table-level parsing with embedded JSON payload extraction across all 24 SQL database snapshots.

3. **Distributed Trace Correlation in Log Analysis**:
   - *Failure*: Readback traces split the lookup identifier (email) and the lookup result (e.g., `rows=0`, `http_status=404`) across separate log entries sharing a `trace_id`.
   - *Fix*: Implemented a trace-correlation engine that gathers all log events by `trace_id` before evaluating resource existence and recreation risk.

4. **Historical Email Hash Resolution**:
   - *Failure*: Central observability logs index records via SHA256 correlation keys. When a user changed their email, older logs cited the hash of their prior email.
   - *Fix*: Integrated SHA256 email hashing across all current and historical emails from `user_identities.csv` and `user_audit_log.csv`.

5. **Temporal Evolution of Resource States**:
   - *Failure*: Early iterations flagged resources as `PRESENT` if any historical snapshot contained them, ignoring subsequent deletion actions.
   - *Fix*: Implemented point-in-time state resolution that selects the latest observation on or before `audit_at`, correctly recognizing post-request deletion and anonymization.
