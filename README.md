# GRC102 Week 4 — Linux Audit & Security Control Assurance Report

**Author:** Hilda Odein Joshua-Jack  
**Reg. No:** C11/26/CGRCE/17247  
**Cohort:** Cohort 11  
**Course:** GRC102 – Information Security Governance  
**Environment:** Kali GNU/Linux Rolling 2026.2 • VirtualBox  
**Submission date:** 03 October 2026

---

## Authorisation Note

This report documents an authorised laboratory assessment. Findings are presented as control-assurance observations and are not represented as confirmed security incidents unless the evidence supports that conclusion.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Authorisation](#2-scope-and-authorisation)
3. [Methodology](#3-methodology)
4. [Evidence Bundle 1: Audit Configuration and Events](#4-evidence-bundle-1-audit-configuration-and-events)
5. [Evidence Bundle 2: Linux Log Analysis](#5-evidence-bundle-2-linux-log-analysis)
6. [Evidence Bundle 3: Lynis Security Assessment](#6-evidence-bundle-3-lynis-security-assessment)
7. [Consolidated Findings and Risk Priorities](#7-consolidated-findings-and-risk-priorities)
8. [Evidence Bundle 4: Control Monitoring and Governance](#8-evidence-bundle-4-control-monitoring-and-governance)
9. [Evidence Bundle 5: SIEM, Automation and Continuous Monitoring](#9-evidence-bundle-5-siem-automation-and-continuous-monitoring)
10. [Remediation and Retest Plan](#10-remediation-and-retest-plan)
11. [Conclusion](#11-conclusion)
12. [Appendix A: Evidence Register](#appendix-a-evidence-register)
13. [Appendix B: Evidence Guide](#appendix-b-evidence-guide)
14. [Appendix C: Finding Records](#appendix-c-finding-records)

---

## 1. Executive Summary

This assessment reviewed the security monitoring and control-assurance posture of an authorised Kali GNU/Linux laboratory environment. The assessment used `audit`, `ausearch`, `aureport`, `journalctl` and `Lynis` to examine audit coverage, privileged activity, system events, logging and security configuration.

The assessment confirmed that the Linux audit subsystem was operational and collecting security-relevant events. Configured audit rules covered changes to `/etc/passwd`, `/etc/shadow`, program execution and writes to `/var/log/auth.log`. Audit records also demonstrated that activity could be associated with the originating user, including cases where the executed process operated with elevated privileges.

The system journal provided additional evidence of privileged activity and system events. No failed logins or failed authentications were identified in the reviewed `aureport` output. Several system errors were present, including a VMware graphics-driver message and desktop service errors. These were treated as operational conditions rather than security incidents because the available evidence did not establish malicious activity.

The latest Lynis assessment reported a **Hardening Index of 61** from **254 tests**. The assessment identified several areas requiring control review, including external logging, file integrity monitoring, password-age configuration, DNS resilience and malware-scanning capability.

The three principal governance issues identified for follow-up are:

1. No evidence of external/centralised security log forwarding, despite local audit and journal logging being available.
2. No dedicated broader file-integrity monitoring capability was demonstrated, although audit provides event monitoring for selected sensitive files.
3. Password maximum-age configuration is effectively unrestricted, with `PASS_MAX_DAYS = 99999` requiring review against the organisation's approved password policy.

### Overall assurance position

These observations are **control-assurance findings** rather than confirmed security incidents. Their final risk classification should depend on the applicable organisational security baseline, risk appetite and control requirements.

---

## 2. Scope and Authorisation

### 2.1 Scope

The assessment covered the authorised Linux laboratory virtual machine and focused on:

- Linux audit configuration
- Security-relevant audit events
- Privileged activity
- Authentication and system logging
- System errors and warnings
- Security configuration and hardening
- Control monitoring and governance implications
- SIEM and continuous-monitoring mapping

### 2.2 Environment

| Item | Observed Value |
|---|---|
| Operating system | Kali GNU/Linux Rolling 2026.2 |
| Kernel | 6.19.14+kali-amd64 |
| Lynis | 3.1.6 |
| Virtualisation | VirtualBox |
| Audit framework | auditd |
| Init/system manager | systemd |
| Assessment type | Authorised laboratory assessment |

### 2.3 Authorisation and Evidence Integrity

Testing was performed within an authorised laboratory environment. Commands were used to inspect system configuration, audit records, system logs and Lynis results. No security setting was changed solely to improve a score. Where a finding requires an organisational policy decision, the report records the observation and recommends review rather than treating the laboratory configuration as an automatic policy violation.

---

## 3. Methodology

The assessment followed four main activities.

### 3.1 Audit Assessment

- Verifying that audit was installed and operational
- Reviewing loaded audit rules using `auditctl`
- Reviewing generated events using `ausearch`
- Reviewing audit summaries using `aureport`

### 3.2 Linux Log Analysis

- Privileged `sudo` sessions
- Audit daemon activity
- System errors and warnings
- Authentication-related activity

The expected `/var/log/auth.log` file was also checked. It was **not present** in the environment, so the systemd journal was used as the available source for authentication and privilege-use evidence.

### 3.3 Lynis Assessment

- System hardening
- Authentication configuration
- Network configuration
- Logging
- File integrity
- Package security
- Malware protection
- System configuration

The latest recorded assessment reported a **Hardening Index of 61**, with **254 tests** performed.

### 3.4 Governance Mapping

- Control objectives
- Responsible owners
- Measurable thresholds
- Risk significance
- Remediation requirements
- Evidence required for retesting

---

## 4. Evidence Bundle 1: Audit Configuration and Events

This evidence bundle demonstrates that the audit service was operational, that the intended rules were loaded, that security-relevant events could be retrieved and that audit summaries could be generated.

### Screenshot 4.1 — Audit daemon status

<img width="602" height="157" alt="image" src="https://github.com/user-attachments/assets/35a3e6c9-971e-427d-bafc-0b41d21dd8bb" />

The audit service is successfully installed and actively running on the Kali Linux system. The service status shows `Active: active (running)` with audit operating as the main process (PID 10800). This confirms that the system is capable of collecting Linux security audit events.

### Screenshot 4.2 — Loaded custom audit rules

```bash
sudo auditctl -l
```

**Output:**

```text
-w /etc/passwd -p rwxa -k passwd_changes
-w /etc/shadow -p rwxa -k shadow_changes
-a always,exit -F arch=b64 -S execve -F key=program_execution
-a always,exit -F arch=b32 -S execve -F key=program_execution
-w /var/log/auth.log -p wa -k auth_failures
```

### 4.3 Audit event retrieved using program_execution key

```bash
sudo ausearch -k program_execution -i | grep -E "type=EXECVE|type=SYSCALL" | tail -6
```

### 4.2 Audit Report Summary

```bash
sudo aureport
```

| Metric | Observed result |
|---|---|
| Time range | 03/10/2026 01:12:23.731 – 03/10/2026 01:51:29.147 |
| Configuration changes | 17 |
| Account/group/role changes | 0 |
| Logins | 0 |
| Failed logins | 0 |
| Authentications | 0 |
| Failed authentications | 0 |
| Users | 3 |
| Executables | 21 |
| Commands | 27 |
| Files | 28 |
| Failed syscalls | 40 |
| Total events | 6,648 |

The audit records demonstrate that the Linux audit subsystem was actively collecting security-relevant events during the assessment. A `program_execution` event recorded at approximately **01:39 on 3 October 2026** identified `hilda` as the original authenticated user (`auid=hilda`) while the executed process, `/usr/sbin/unix_chkpwd`, operated with root privileges. The execution was successful and was associated with the configured `program_execution` audit key.

From a security governance perspective, this demonstrates **accountability and traceability for privileged activity**. The distinction between the original user and the effective privileged identity is particularly useful because it helps security teams establish who initiated an action even when the process subsequently operates with elevated privileges.

The `aureport` summary further confirms that the audit system was collecting a substantial volume of events during the assessment period, including executable, command, file, process and configuration-related activity. **No login or failed authentication events** were recorded during the period reviewed.

> **Important classification**
>
> `aureport` reported **40 failed syscalls**. These must not be described as 40 failed login attempts. Failed syscalls and failed authentication events are **different event categories**.

---

## 5. Evidence Bundle 2: Linux Log Analysis

System activity was reviewed using `journalctl` because `/var/log/auth.log` was not present in the laboratory environment. The systemd journal therefore served as the available source for privilege-use and system-event evidence.

### Screenshot 5.1 — Recent journal activity

```bash
sudo journalctl --since "today" | tail -20
```

Recent system activity was reviewed using `journalctl`. The journal recorded normal privileged activity involving `sudo`, including sessions opened by user `hilda` to execute commands as root. The journal also recorded an auditd log rotation event at approximately **02:04 on 3 October 2026**.

### Screenshot 5.2 — SSH / authentication activity

```bash
sudo journalctl -u ssh --since "today"
sudo journalctl -u ssh
```

**Result:** No entries — no SSH authentication activity was recorded during the review period.

### 5.1 Authentication and Privilege-Use Evidence

The Kali Linux VM does not provide `/var/log/auth.log`; therefore, the system journal was used as the equivalent authentication and privilege-use evidence source. `journalctl` records `sudo` activity showing user `hilda` initiating privileged sessions as root, including the command executed and the opening and closing of the privileged session. This provides useful accountability for administrative activity.

### 5.2 Error and Warning Analysis

The error-level journal review identified a `vmwgfx` graphics-driver message stating that the driver appeared to be running on an unsupported hypervisor, together with desktop/session service errors involving `gkr-pam` and `obexd`. The laboratory environment is a VirtualBox guest. These messages were therefore treated as **operational virtualisation or desktop-service conditions** rather than evidence of malicious activity.

#### a. Error evidence

```bash
sudo journalctl -p err --since "today" -n 10
```

**Observed:**

- `vmwgfx` — driver running on an unsupported hypervisor
- `gkr-pam` — unable to locate daemon control file
- `obexd` — unable to acquire registry

#### b. Warning evidence

```bash
sudo journalctl -p warning --since "today" -n 10
```

**Observed:**

- `clocksource` — long readout interval
- `upower` — failed to get percentage
- `bluetooth` / `bluez` — system service not available
- `rtkit-daemon` — canary thread apparently starving

### 5.3 Module 2 Conclusion

| Event/Condition | Evidence Source | Time | User/Service | Security Significance | Recommended Action |
|---|---|---|---|---|---|
| Privileged sudo session | systemd journal | 02:04, 3 Oct 2026 | hilda / sudo | Provides accountability for administrative activity and records the transition to root privileges. | Continue monitoring privileged activity and retain relevant logs. |
| Audit log rotation | systemd journal | 02:04:14, 3 Oct 2026 | auditd | Indicates that the audit daemon is actively managing its log files. | Monitor audit log rotation and ensure logs are retained according to policy. |
| VM graphics driver error | systemd journal | 00:55:20, 3 Oct 2026 | kernel / vmwgfx | Indicates a virtualisation configuration issue. Operational rather than evidence of malicious activity based on the available record. | Review the VM graphics configuration and compatibility settings. |
| Desktop/session service error | systemd journal | 00:56:04, 3 Oct 2026 | obexd | Indicates a service-level error involving a desktop data service. No direct security incident is established from this event alone. | Monitor for recurrence and investigate if the error affects functionality. |

The review demonstrated that the Kali VM is actively generating and retaining system and security-related journal events. Privileged activity performed through `sudo` was identifiable by user and command, while audit log rotation was also recorded. Several error-level events were observed, primarily relating to the VM graphics driver and desktop services. These were treated as operational conditions rather than security incidents because the available evidence does not indicate unauthorised activity. Continued monitoring and investigation of recurring errors is recommended.

---

## 6. Evidence Bundle 3: Lynis Security Assessment

### Screenshot 6.1 — Lynis version/report metadata

```bash
sudo cat /var/log/lynis-report.dat
```

**Key metadata:**

```text
report_version_major=1
report_version_minor=0
report_datetime_start=2026-10-03 03:04:49
auditor=[Not Specified]
lynis_version=3.1.6
os=Linux
os_name=Kali Linux
os_fullname=Kali GNU/Linux Rolling
os_version=Rolling release
linux_version=Kali
os_kernel_version=6.19.14+kali
os_kernel_version_full=6.19.14+kali-amd64
hostname=hilda
test_category=all
test_group=all
plugin_directory=/etc/lynis/plugins
lynis_update_available=0
vm=1
vmtype=virtualbox
container=0
notebook=1
systemd=1
hostid=3c883280901181fe49e22536fc4d3725eb000098a
hostid2=ec2754ce6aa4f6c083c81378105c668e8750ff56897eaa0b883b8467f0b7e3d6
```

### Screenshot 6.2 — Lynis baseline assessment summary

**Initial**

```text
Hardening index : 60
Tests performed : 253
Plugins enabled : 1
```

**Retest**

```bash
sudo grep -E "Hardening index|Tests performed|Plugins enabled|Warnings|Suggestions" /var/log/lynis.log | tail -20
```

```text
2026-10-03 02:48:38 Hardening index : [61]
2026-10-03 02:48:51 Tests performed: 254
```

The initial Lynis assessment reported a **Hardening Index of 60** based on **253 tests**, with one plugin enabled. A subsequent assessment reported an index of **61** based on **254 tests**. The latest assessment is used as the current baseline, while the earlier result is retained as evidence of the initial scan.

> **Baseline interpretation**
>
> The change from 60/253 to 61/254 must **not** be presented as improvement caused by remediation. No hardening change was implemented during the assessment. The difference reflects a later assessment with one additional test.

### Screenshot 6.3 — Lynis findings

```bash
sudo grep -E "warning|suggestion" /var/log/lynis.log | tail -40
```

### 6.1 Prioritised Lynis Findings

| ID | Lynis finding | Test ID | Governance relevance |
|---|---|---|---|
| F1 | External logging is not enabled | LOGG-2154 | High |
| F2 | Dedicated broader file-integrity monitoring is not demonstrated | FINT-4350 | High |
| F3 | Maximum password age is effectively unrestricted | AUTH-9286 | Medium |
| F4 | Malware scanning capability is not established by the lab | HRDN-7230 | Medium |
| F5 | DNS resolver availability requires validation | NETW-2705 | Medium / validation required |

### 6.2 F1 — External logging

**Suggestion:** Enable logging to an external logging host for archiving purposes and additional protection. **Test:** LOGG-2154.

**Control objective:** Ensure security logs are protected from loss, tampering or destruction on the originating system and remain available for monitoring and investigation.

**Observed condition:** Lynis recommends sending logs to an external logging host.

**Risk:** If important logs exist only on the local system, an attacker with sufficient privileges could potentially alter or remove evidence on that system. Local storage also creates dependency on host availability and retention.

**Recommended remediation:** Implement centralised log collection using an approved logging or SIEM platform. Forward security-relevant audit and system logs and protect them according to retention and access requirements.

**Likely owner:** IT Operations / Security Operations, with CISO or Security Governance oversight.

**Priority:** High

**Retest evidence:** Demonstrate that logs from the Linux host are being received by the central platform and that timestamps, source host information and relevant audit events are retained.

### 6.3 F2 — File integrity monitoring

**Suggestion:** Install a file integrity tool to monitor changes to critical and sensitive files. **Test:** FINT-4350.

**Control objective:** Detect unauthorised changes to critical system files.

**Observed condition:** Lynis recommends installing a file integrity monitoring capability.

**Risk:** Unauthorised modification of critical system files may not be detected promptly if there is no dedicated integrity monitoring mechanism.

**Recommended remediation:** Evaluate and deploy an approved file integrity monitoring solution for critical system files and configuration directories. Configure appropriate alerting and review procedures.

**Likely owner:** Security Operations / IT Security

**Priority:** High

**Retest evidence:** Generate an authorised test change to a monitored file in an approved test environment and demonstrate that the integrity monitoring solution detects and records the change.

### 6.4 F3 — Maximum password age

**Suggestion:** Configure maximum password age in `/etc/login.defs`. **Test:** AUTH-9286.

**Control objective:** Support appropriate password lifecycle management.

**Observed condition:** Lynis identified that a maximum password age should be configured in `/etc/login.defs`. `PASS_MAX_DAYS` is **99999** and `chage` confirms the account-level value.

**Risk:** Without an appropriate password ageing policy, passwords may remain unchanged indefinitely, increasing potential exposure if credentials are compromised.

**Recommended remediation:** Review the organisation's password policy and configure an appropriate maximum password age where required. **Do not change the lab setting without approval.**

**Likely owner:** IT Operations / Identity and Access Management

**Priority:** Medium

**Retest evidence:** Verify the relevant `/etc/login.defs` setting and confirm newly created accounts inherit the intended password-age configuration.

### 6.5 F4 — Malware scanning

**Suggestion:** Harden the system by installing at least one malware scanner to perform periodic filesystem scans. **Test:** HRDN-7230.

**Control objective:** Provide a mechanism for detecting potentially malicious files or software.

**Observed condition:** Lynis recommends a malware scanning capability. The lab did not independently establish whether an enterprise endpoint solution exists.

**Risk:** Without an appropriate malware detection mechanism, malicious files or unwanted software may not be identified through a dedicated scanning process.

**Recommended remediation:** Assess whether malware scanning is required for the system's role and risk profile. Where appropriate, deploy an approved endpoint or malware detection solution.

**Likely owner:** IT Security / Endpoint Security

**Priority:** Medium

**Retest evidence:** Demonstrate that the approved scanner is installed, operational and capable of completing a scheduled or authorised test scan.

### 6.6 F5 — DNS Resolver Availability

**Observed condition:** Lynis reported that two responsive nameservers could not be identified.

**Security significance:** Unreliable DNS configuration can affect system connectivity, package updates, security tooling and communication with monitoring services. The finding requires validation before being classified as a security weakness.

**Recommended action:** Review the VM's DNS configuration and confirm that appropriate primary and secondary resolvers are available and responsive.

**Priority:** Medium / validation required.

### 6.7 Password Age Verification

```bash
sudo grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs
sudo chage -l hilda
```

| Setting | Evidence |
|---|---|
| Last password change | 2 Oct 2026 |
| Password expires | 17 Jul 2300 |
| Maximum password age | 99,999 days |
| Minimum password age | 0 days |
| Warning period | 7 days |
| Account expiry | Never |
| Password inactive | Never |

The `chage` output confirms that the `PASS_MAX_DAYS = 99999` configuration is reflected on the user account. This is a control observation that should be assessed against the approved authentication policy **before any change is implemented**.

### 6.8 File Integrity Monitoring Distinction

Lynis reported **FINT-4350** and recommended a file integrity tool. The system does, however, have audit rules monitoring changes to `/etc/passwd` and `/etc/shadow`. This provides useful event-level accountability for selected sensitive files but **does not constitute comprehensive file integrity monitoring** across critical system files.

> **Evidence integrity point**
>
> The report therefore does **not** state that the system has no monitoring. It states that dedicated broader FIM was not demonstrated, while audit provides event-based monitoring for selected sensitive files.

### 6.9 Module 3 Conclusion

The Lynis assessment provides a structured view of configuration and hardening areas requiring review. The principal governance-relevant observations concern external logging, broader file integrity monitoring and password ageing, with DNS and malware capability requiring further validation or assessment. No hardening change was implemented during the assessment, so the findings are documented for risk-based remediation rather than changes made solely to increase the Lynis score.

---

## 7. Consolidated Findings and Risk Priorities

The following findings consolidate the technical evidence into control-assurance observations. Priority reflects the governance relevance identified in this laboratory report, **not** a formal enterprise risk score.

| Finding | Evidence | Control issue | Owner | Priority |
|---|---|---|---|---|
| Password maximum age effectively unrestricted | Lynis AUTH-9286; `PASS_MAX_DAYS=99999`; `chage` confirms 99,999 days | Password lifecycle control may not adequately limit prolonged credential validity | IAM / IT Operations | Medium |
| No external log forwarding demonstrated | Lynis LOGG-2154; local audit/journal evidence exists | Limited resilience and central monitoring visibility | Security Operations / IT | High |
| No dedicated broader FIM demonstrated | Lynis FINT-4350; audit monitors `/etc/passwd` and `/etc/shadow` | Selected event monitoring exists, but broader integrity monitoring is not established | Security Operations | High |
| Malware scanning capability not established by lab | Lynis HRDN-7230 | Capability requires assessment against the applicable endpoint standard | Endpoint Security / IT Security | Medium |
| DNS resolver availability requires validation | Lynis NETW-2705 | Two responsive nameservers could not be identified | IT Operations | Medium / validation |

---

## 8. Evidence Bundle 4: Control Monitoring and Governance

### 8.1 Governance Issues Identified

1. Security logging is not configured for external forwarding, based on Lynis LOGG-2154.
2. A dedicated file integrity monitoring capability is not established, based on Lynis FINT-4350, although audit already monitors `/etc/passwd` and `/etc/shadow`.
3. The password maximum-age configuration is effectively unrestricted, with `PASS_MAX_DAYS=99999`, confirmed at both system and user-account level.
4. A DNS resolver availability warning was identified, with Lynis reporting that two responsive nameservers could not be found.
5. Malware scanning capability was not identified by the Lynis assessment, which generated recommendation HRDN-7230.

> **Governance interpretation**
>
> A Lynis suggestion is **not automatically a control failure**. The governance significance depends on the applicable control requirement, risk assessment, persistence and approved thresholds.

### 8.2 Control Monitoring Table

| Control / Objective | Evidence | Owner | Observed Status | KPI / KRI or Threshold | Risk / Significance | Remediation | Retest / Follow-up |
|---|---|---|---|---|---|---|---|
| **Centralised security logging.** Ensure security-relevant logs are retained and available outside the originating host. | Lynis LOGG-2154 recommends external logging. Audit and journalctl generate local security evidence. | Security Operations / IT Operations | Needs improvement. Local evidence exists, but external forwarding was not established in the lab. | 100% of in-scope production hosts forwarding required security logs to the central monitoring platform. | Loss or compromise of the host could affect availability or integrity of locally stored evidence and reduce central monitoring visibility. | Configure approved central log forwarding/SIEM integration and define retention and access requirements. | Verify test events appear centrally with correct timestamp, hostname and event details. |
| **Audit logging and accountability.** Maintain traceability of security-relevant activity. | `auditctl -l` showed rules for `/etc/passwd`, `/etc/shadow`, `execve` and `/var/log/auth.log`. | IT Security / Security Operations | Partially implemented. Audit is active, but coverage is limited to configured rules. | Audit service available; 100% of critical systems have approved audit rules; no unexplained coverage gaps. | Inadequate audit coverage can reduce investigation capability and accountability. | Review audit rule coverage against the Linux security baseline and expand where justified. | Run `auditctl -l`, generate approved test events and confirm expected records are captured. |
| **Password lifecycle management.** Ensure password ageing aligns with approved authentication policy. | Lynis AUTH-9286; `PASS_MAX_DAYS=99999`; `chage` confirms 99,999 days. | IAM / IT Operations | Needs review. Maximum age is effectively unrestricted. | 100% of in-scope accounts comply with approved password policy. | Very long password validity can reduce credential lifecycle effectiveness if a password is compromised. | Review against approved policy and establish an appropriate value if required. Do not change without approval. | Verify `/etc/login.defs` and `chage -l` on test accounts after approved change. |
| **File integrity monitoring.** Detect unauthorised changes to critical system files. | Lynis FINT-4350; audit monitors `/etc/passwd` and `/etc/shadow`. `/etc/group` and `/etc/shadow` are not included in displayed rules. | Security Operations / IT Security | Partially implemented. Selected event monitoring exists, but dedicated broader FIM was not established. | 100% of critical systems covered by an approved integrity-monitoring mechanism where required. | Unauthorised changes may not be detected comprehensively or consistently. | Assess and deploy approved FIM or formally document why existing controls are sufficient. | Test an authorised change to a monitored file and verify detection, alerting and recording. |
| **DNS availability and resilience.** Maintain reliable name resolution for security and operational services. | Lynis NETW-2705: two responsive nameservers could not be identified. | IT Operations / Network Team | Requires validation. | Required primary/secondary DNS resolvers available and responsive; no unresolved DNS exceptions. | DNS problems can affect connectivity, package updates, monitoring and security tooling. | Review resolver configuration and confirm appropriate primary and secondary DNS services. | Test configured resolvers and rerun relevant checks. |
| **Malware detection.** Maintain appropriate endpoint/malware detection capability. | Lynis HRDN-7230 recommended a malware scanner. Lab did not establish whether an enterprise endpoint solution exists. | Endpoint Security / IT Security | Requires assessment rather than confirmed control failure. | 100% of applicable production endpoints covered by approved malware/endpoint protection. | Lack of appropriate detection could delay identification of malicious files or software. | Confirm endpoint-security standard and deploy or verify approved protection where required. | Verify agent/protection status and complete an authorised test scan or management-console health check. |

### 8.3 Why These Are Governance Issues

The important distinction is between an individual technical observation and a control that management needs to monitor. The `vmwgfx` errors found in `journalctl` are primarily operational and do not, on the evidence available, demonstrate a security control failure.

Similarly, `aureport` reported **0 failed logins**, **0 failed authentications** and **40 failed syscalls**. The 40 failed syscalls should **not** be reported as 40 failed login attempts. They are different event categories.

### 8.4 Retest Criteria

**Audit coverage**  
Approved audit rules are loaded. Controlled test events generate expected records. Coverage gaps are documented and reviewed.

**Central logging**  
Forwarding configuration is active. Test events are received centrally with correct timestamp, hostname and event details. Retention requirements are met.

**Password policy**  
`/etc/login.defs` matches approved policy. `chage -l` on test accounts reflects the approved configuration.

**FIM**  
Approved FIM tool is installed. Monitored file set is defined. A controlled test modification generates an expected detection. The resulting alert is recorded.

**DNS**  
Resolver testing shows required DNS servers respond successfully.

**Malware protection**  
Approved endpoint-management platform shows protection installed, enabled and reporting successfully.

### 8.5 When and How Should Controls Be Retested?

Retesting should happen **after remediation has been implemented and before the finding is formally closed**. A sensible workflow is:

```text
Finding → Owner → Deadline → Remediation → Evidence → Retest → Review → Close / Escalate
```

For higher-risk findings, retesting should occur promptly after remediation. For recurring controls such as logging, audit coverage and endpoint protection, testing should also become part of continuous or scheduled control monitoring rather than waiting for the next annual audit.

---

## 9. Evidence Bundle 5: SIEM, Automation and Continuous Monitoring

### 9.1 Purpose

The Linux assessment generated evidence from three main sources: `audit` for security events, privileged activity and monitored file changes; `journalctl` for system, service, authentication and privilege-use events; and `Lynis` for security configuration and hardening assessment. In an enterprise environment, these sources could feed a central monitoring architecture where technical events are collected, normalised, correlated and assessed against defined security and control requirements.

### 9.2 Linux Evidence to Enterprise Monitoring

| Evidence Source | Laboratory Evidence | Enterprise Monitoring Use | Example Alert / Use Case |
|---|---|---|---|
| audit | `/etc/passwd` and `/etc/shadow` monitoring | Forward security audit events to SIEM | Alert when sensitive account files are modified |
| audit | `program_execution` events | Monitor selected privileged/security-sensitive process execution | Investigate unexpected privileged process execution |
| audit | User and effective identity information | Support accountability and user attribution | Correlate privileged activity with originating user |
| journalctl | `sudo` session activity | Monitor administrative privilege use | Alert/review unusual administrative activity |
| journalctl | auditd log rotation | Monitor audit service health | Escalate if logging stops or storage becomes unavailable |

### 9.3 Continuous Monitoring Model

```text
LINUX HOSTS → auditd / journalctl / Lynis → LOG / DATA COLLECTION → SIEM
→ TECHNICAL ALERT or CONTROL SIGNAL → IT/SOC or GRC/SECURITY ASSURANCE
→ RISK / GOVERNANCE → REMEDIATION & RETEST
```

### 9.4 Technical Alerts Versus Governance Escalation

Not every event should become a governance escalation. A single `vmwgfx` driver error is primarily an operational/technical alert. An isolated `obexd` service error would normally remain an operational issue unless it becomes persistent, affects a security control or indicates a broader security problem.

| Condition | Classification | Initial Owner | Governance Escalation? |
|---|---|---|---|
| One VMware driver error | Technical operational issue | IT Operations | No, unless persistent/impacting service |
| Routine sudo activity by authorized user | Security monitoring event | SOC / IT | No |
| Unexpected modification of `/etc/shadow` | Security incident | SOC / IT Security | Potentially, depending on investigation |
| Auditd stops collecting events | Control failure | IT Security / IT Operations | Yes if monitoring requirement is breached |
| Production host stops forwarding security logs | Control failure | Security Operations | Yes |
| Password policy repeatedly outside approved standard | Control-assurance issue | IAM | Yes |
| Critical systems lack approved integrity monitoring | Control gap | Security Operations | Yes |
| Isolated low-risk Lynis suggestion | Improvement opportunity | IT Operations | Normally no |
| Repeated high-risk Lynis findings across production estate | Systemic control weakness | IT Security / GRC | Yes |

### 9.5 Example Automated Controls

| Control | Automated Test | Trigger | Action |
|---|---|---|---|
| Audit logging | Check audit service status | audit stopped | SOC/IT alert |
| Sensitive-file monitoring | Monitor `/etc/passwd` and `/etc/shadow` changes | Unauthorized change | Security investigation |
| Privileged access | Analyze `sudo` events | Unusual/unauthorised activity | SOC investigation |
| Central logging | Check log forwarding status | Host stops sending logs | Create control exception |
| Password policy | Periodically test password-age | Outside approved standard | IAM remediation |

### 9.6 Automation and Workflow

1. **Detect:** SIEM, endpoint tooling or scheduled control checks identify an event or control deviation.
2. **Validate:** Determine whether the event is expected, authorised or a genuine control exception.
3. **Classify:** Classify the condition as an operational event, security event, security incident, control exception or governance issue.
4. **Assign:** An automated workflow assigns the issue to the appropriate owner.
5. **Escalate:** Issues exceeding defined severity, duration or recurrence thresholds are escalated to Security Governance, Risk or management.
6. **Remediate:** The responsible owner implements corrective action.
7. **Retest:** The original control test is repeated.
8. **Close:** The issue is closed only when objective evidence demonstrates that the control is operating as expected.

### 9.7 Governance Thresholds

Security Governance escalation should be considered when:

- a security control is disabled or absent;
- a control remains outside its approved threshold beyond the defined remediation period;
- the same control failure occurs repeatedly across multiple systems;
- security logging or audit evidence becomes unavailable;
- a privileged activity event cannot be adequately attributed to an authorised user;
- a critical security configuration is changed without approval;
- a high-risk finding remains unresolved beyond its agreed due date;
- risk exceeds the organisation's defined appetite or tolerance.

### 9.8 Evidence Bundle 5 Conclusion

The laboratory evidence demonstrates how host-level security data can support enterprise security monitoring and continuous control assurance. Audit provides detailed security event and accountability information, `journalctl` provides system and privilege-use evidence, while Lynis provides periodic assessment of security configuration and hardening. In an enterprise environment, these sources could be integrated with a SIEM to support centralised collection, correlation, alerting and reporting.

Not every technical event should result in governance escalation. Routine service errors and expected administrative activity can remain within IT operations or SOC workflows. Governance escalation becomes appropriate when evidence indicates that a security control is absent, ineffective, repeatedly failing or outside an approved threshold. Examples from this assessment include the absence of demonstrated external log forwarding, the need for broader file integrity monitoring and password configuration outside an approved policy baseline.

A continuous monitoring model should therefore combine automated technical detection with defined control thresholds, ownership, escalation and retesting. This allows security teams to respond to individual events while enabling GRC functions to identify recurring or systemic control weaknesses and obtain objective evidence of remediation.

---

## 10. Remediation and Retest Plan

| ID | Finding | Primary Owner | Recommended Action | Target Evidence | Retest Method | Closure Condition |
|---|---|---|---|---|---|---|
| F1 | External/centralised logging not demonstrated | Security Operations / IT Operations | Implement approved central log forwarding/SIEM integration. | Forwarding configuration, host registration, sample event and retention evidence. | Generate controlled audit event and verify central receipt, timestamp and source identity. | Required logs are centrally received and retained according to policy. |
| F2 | Dedicated broader FIM not demonstrated | Security Operations / IT Security | Assess and deploy approved FIM or document control sufficiency. | FIM deployment/configuration or approved compensating-control rationale. | Controlled test change produces expected detection. | Approved integrity-control requirement is met and evidenced. |
| F3 | `PASS_MAX_DAYS=99999` | IAM / IT Operations | Review approved password policy and implement only after authorisation. | Approved policy and updated configuration where required. | Verify `login.defs` and test-account `chage` output. | Configuration aligns with approved policy. |
| F4 | Malware capability not established by lab | Endpoint Security / IT Security | Confirm endpoint-security standard and protection coverage. | Management-console health evidence or approved scanner status. | Verify protection status and authorised test scan/health check. | Applicable endpoints meet the approved protection requirement. |
| F5 | DNS resolver availability warning | IT Operations / Network | Validate resolver configuration and availability. | Resolver configuration and successful test results. | Test required primary/secondary resolvers and rerun relevant check. | DNS requirement is met or exception is formally accepted. |

### 10.1 Retest Workflow

```text
Finding identified → Owner assigned → Remediation deadline agreed → Remediation implemented
→ Evidence collected → Control retested → Result reviewed → Finding closed or escalated
```

For higher-risk findings, retesting should occur promptly after remediation. Recurring controls should then be incorporated into continuous or scheduled monitoring. Closure should be evidence-based and should not rely solely on an owner's verbal confirmation.

---

## 11. Conclusion

The Linux assessment demonstrates that technical security evidence can be converted into measurable control-assurance activities. Audit and journalctl provide evidence of security events and system activity, while Lynis provides a structured assessment of security configuration and hardening.

The assessment identified several conditions requiring review, including the absence of demonstrated external log forwarding, the lack of dedicated file integrity monitoring, an effectively unrestricted password maximum-age configuration and a DNS resolver warning. The malware-scanning recommendation also requires assessment against the applicable endpoint-security standard rather than being treated as a confirmed enterprise control failure.

These conditions should not all be treated as security incidents. Their governance significance depends on whether they represent a failure to meet an approved control requirement, whether they persist, and whether they exceed defined risk or control thresholds. Assigning clear owners, defining measurable thresholds and requiring objective remediation evidence allows security governance to distinguish routine technical issues from control weaknesses requiring management attention.

> **Key assurance principle**
>
> DETECT → ASSIGN → REMEDIATE → RETEST → RETAIN EVIDENCE
>
> This creates a traceable link between Linux-level technical activity and enterprise security governance.

---

## Appendix A: Evidence Register

| Evidence ID | Evidence Item | Source / Command | Report Location |
|---|---|---|---|
| E1 | Audit service status | `systemctl status auditd` | Section 4 / Screenshot 4.1 |
| E2 | Loaded audit rules | `sudo auditctl -l` | Section 4 / Screenshot 4.2 |
| E3 | Program execution audit event | `sudo ausearch -k program_execution -i` | Section 4 / Screenshot 4.3 |
| E4 | Audit summary | `sudo aureport` | Section 4 / Screenshot 4.4 |
| E5 | Recent system journal | `sudo journalctl --since "today" -n 8` | Section 5 / Screenshot 5.1 |
| E6 | Authentication/privilege review | `journalctl` sudo activity | Section 5 / Screenshot 5.2 |
| E7 | Error-level journal review | `sudo journalctl -p err --since "today" -n 10` | Section 5 / Screenshot 5.3 |
| E8 | Live journal review | `journalctl` live-event review | Section 5 / Screenshot 5.4 |
| E9 | Lynis metadata | `/var/log/lynis-report.dat` / Lynis output | Section 6 / Screenshot 6.1 |
| E10 | Lynis baseline/current summary | Lynis assessment output | Section 6 / Screenshot 6.2 |
| E11 | Lynis findings | Lynis suggestions/output | Section 6 / Screenshot 6.3 |
| E12 | Password configuration | `/etc/login.defs` and `chage -l hilda` | Section 6 / Screenshot 6.4 |
| E13 | Audit sensitive-file controls | `auditctl -l` | Section 6 / Screenshot 6.5 |

---

## Appendix B: Evidence Guide

### B1 — Audit service status

```bash
sudo systemctl status auditd
```

### B2 — Loaded audit rules

```bash
sudo auditctl -l
```

### B3 — Audit event

```bash
sudo ausearch -k program_execution -i | grep -E "type=EXECVE|type=SYSCALL" | tail -6
```

### B4 — Aureport

```bash
sudo aureport
```

### B5 — Journal review

```bash
sudo journalctl --since "today" | tail -20
```

### B6 — SSH/authentication activity

```bash
sudo journalctl -u ssh --since "today"
sudo journalctl -u ssh
```

### B7 — System errors

```bash
sudo journalctl -p err --since "today" -n 10
```

### B8 — Live events

```bash
sudo journalctl --since "today" -n 8
sudo journalctl -f
```

### B9 — Error-level journal

```bash
sudo journalctl -p err --since "today" -n 10
```

### B10 — Lynis metadata

```bash
sudo cat /var/log/lynis-report.dat
```

### B11 — Lynis findings

```bash
sudo grep -E "warning|suggestion" /var/log/lynis.log | tail -40
```

### B12 — Password verification

```bash
sudo grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs
sudo chage -l hilda
```

### B13 — Existing auditd controls

```bash
sudo auditctl -l
```

---

## Appendix C: Finding Records

### F1 — External / centralised logging

**Evidence:** Lynis LOGG-2154; local audit/journal evidence is available.

**Security / control significance:** Central monitoring and independent evidence retention are not demonstrated.

**Recommended action:** Implement approved central log forwarding and verify receipt/retention.

### F2 — Dedicated broader FIM

**Evidence:** Lynis FINT-4350; auditd monitors `/etc/passwd` and `/etc/shadow`.

**Security / control significance:** Selected event monitoring exists, but broader integrity monitoring is not established.

**Recommended action:** Assess and deploy approved FIM or document sufficient compensating controls.

### F3 — Password maximum age

**Evidence:** AUTH-9286; `PASS_MAX_DAYS=99999`; `chage` confirms 99,999 days.

**Security / control significance:** Password validity may be longer than an approved credential lifecycle requirement.

**Recommended action:** Review policy and implement only after approval.

### F4 — Malware scanning capability

**Evidence:** HRDN-7230; lab did not establish enterprise endpoint coverage.

**Security / control significance:** Capability may require confirmation against the endpoint-security standard.

**Recommended action:** Verify approved endpoint protection and coverage.

### F5 — DNS resolver availability

**Evidence:** NETW-2705; two responsive nameservers could not be identified.

**Security / control significance:** Potential resilience/availability concern requiring validation.

**Recommended action:** Review resolver configuration and test required DNS services.

---

## Final Checklist Submission

- [x] The report is submitted in the required format.
- [x] All required sections are present and complete.
- [x] Evidence Bundle 1 (Audit Configuration and Events) is included.
- [x] Evidence Bundle 2 (Linux Log Analysis) is included.
- [x] Evidence Bundle 3 (Lynis Security Assessment) is included.
- [x] Evidence Bundle 4 (Control Monitoring and Governance) is included.
- [x] Evidence Bundle 5 (SIEM, Automation and Continuous Monitoring) is included.
- [x] Consolidated findings and risk priorities are documented.
- [x] Remediation and retest plan is provided.
- [x] Conclusion is included.
- [x] Appendix A: Evidence Register is complete.
- [x] Appendix B: Evidence Guide is complete.
- [x] Appendix C: Finding Records is complete.
- [x] All screenshots and command outputs are referenced.
- [x] Authorisation note is included.
- [x] Report is ready for submission.

---

*GRC102 Week 4 Practical Laboratory • Hilda Odein Joshua-Jack • 03 October 2026*
