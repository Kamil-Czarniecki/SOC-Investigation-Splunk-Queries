# SOC Splunk SPL Cheat Sheet

A collection of Splunk (SPL) queries used during SOC investigations: authentication, endpoint activity, web/proxy traffic, phishing triage, network, asset/identity enrichment and cloud.

## How to use

- Replace every `<PLACEHOLDER>` with a real value before running the query (users, hosts, URLs, IPs, indexes).
- Queries using `` `summariesonly` ``, `` `drop_dm_object_name()` ``, `` `security_content_ctime()` `` and `` `get_identity4events()` `` rely on macros from **CIM / Splunk ES / ESCU** (or your own equivalents).
- Index, sourcetype, lookup and field names are environment-specific. Adjust them to your Splunk deployment.
- URLs are **defanged** (`.` → `[.]`) in the output so they are safe to paste into tickets and chats.

## Table of contents

| # | Section | Area |
|---|---------|------|
| 1 | [Authentication data model](#1-authentication-data-model-events) | Identity |
| 2 | [Authentication data model – first/last seen](#2-authentication-data-model--firstlast-seen) | Identity |
| 3 | [Windows logon events](#3-windows-logon-events) | Identity |
| 4 | [OneLogin events](#4-onelogin-events) | Identity |
| 5 | [Process creation on a host](#5-process-creation-on-a-host) | Endpoint |
| 6 | [User activity on endpoints](#6-user-activity-on-endpoints) | Endpoint |
| 7 | [Service account activity](#7-service-account-activity) | Endpoint |
| 8 | [Web data model – by user](#8-web-data-model--by-user) | Web |
| 9 | [Web data model – by URL (identify clickers)](#9-web-data-model--by-url-identify-clickers) | Web |
| 10 | [Proxy logs by host](#10-proxy-logs-by-host) | Web |
| 11 | [Proxy search by URL](#11-proxy-search-by-url) | Web |
| 12 | [Emails containing a URL](#12-emails-containing-a-url) | Phishing |
| 13 | [Proofpoint TAP – summary](#13-proofpoint-tap--summary) | Phishing |
| 14 | [Proofpoint TAP – permitted clicks](#14-proofpoint-tap--permitted-clicks) | Phishing |
| 15 | [Attachment name pattern → hash](#15-attachment-name-pattern--hash) | Phishing |
| 16 | [Network traffic data model](#16-network-traffic-data-model) | Network |
| 17 | [NAC search for rogue devices](#17-nac-search-for-rogue-devices) | Network |
| 18 | [Asset lookup – bulk IPs](#18-asset-lookup--bulk-ips) | Enrichment |
| 19 | [Identity lookup – bulk users](#19-identity-lookup--bulk-users) | Enrichment |
| 20 | [AWS GuardDuty network traffic stats](#20-aws-guardduty-network-traffic-stats) | Cloud |
| 21 | [Azure resource activity](#21-azure-resource-activity) | Cloud |
| 22 | [Find indexes containing a string](#22-find-indexes-containing-a-string) | Utility |
| 23 | [Snippet: defang URLs](#23-snippet-defang-urls) | Utility |
| 24 | [Snippet: first/last event time](#24-snippet-firstlast-event-time) | Utility |

---

## Identity

### 1. Authentication data model (events)

Lists authentication events for a user from the CIM `Authentication` data model, with an ISO 8601 UTC timestamp for easy copy/paste into reports.

```spl
| from datamodel:"Authentication"."Authentication"
| search Authentication.user="<USER>" OR Authentication.src_user="<USER>" OR user="<USER>" OR src_user="<USER>"
| table _time app signature src src_user authentication_method dest
| eval utc_time=strftime(_time, "%Y-%m-%dT%H:%M:%S.%3N%z")
| sort 0 _time
```

### 2. Authentication data model – first/last seen

Quick check whether a user has authenticated to a given destination and when it happened first and last.

```spl
| tstats earliest(_time) as earliestEvent latest(_time) as latestEvent count
    from datamodel=Authentication.Authentication
    where Authentication.user="<USER>" AND Authentication.dest="<DEST>"
    fillnull_value="-"
| convert ctime(earliestEvent) ctime(latestEvent)
```

### 3. Windows logon events

Windows security events for a user or host, sorted chronologically.

| EventCode | Meaning |
|-----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned to new logon |
| 4776 | NTLM credential validation |
| 4748 | Security-disabled local group deleted |

```spl
index IN ("<INDEX1>", "<INDEX2>") "<USER_OR_HOST>" EventCode IN (4776, 4624, 4625, 4672, 4748)
| fillnull value=NULL
| table _time dvc EventCode signature AuthenticationPackageName src_nt_domain src_nt_host src_asset src_dns src_user dest_nt_domain source_workstation src_ip Error_Code PackageName TargetUserName TargetDomain TargetUserSid
| sort 0 _time
```

### 4. OneLogin events

Summarises OneLogin activity per user and IP, excluding noisy event types (`248`, `254`).

```spl
index="<ONELOGIN_INDEX>" NOT event_type_id IN (248, 254) user IN ("<USER>")
| eval events=event_type_id." - ".event_name
| stats count earliest(_time) as earliestTime latest(_time) as latestTime values(events) as events values(app) as apps by user_name, user, ipaddr
| `security_content_ctime(earliestTime)`
| `security_content_ctime(latestTime)`
| table user_name user ipaddr earliestTime latestTime events apps count
```

---

## Endpoint

### 5. Process creation on a host

Process creation events (Windows Security `4688`) for a host, optionally filtered by process name (e.g. an `.exe`).

```spl
index=wineventlog EventCode=4688 host="<HOST>" process_name="<PROCESS_NAME>"
| table _time user user_email parent_process process_name CommandLine
```

### 6. User activity on endpoints

Process activity of a user on workstation endpoints. Replace `<HOST>` with a host name or fragment.

```spl
index="<WORKSTATION_INDEX>" *<HOST>* user=*
| table _time user src_user parent_process_name dest New_Process_Name CommandLine
| sort 0 _time
```

### 7. Service account activity

Activity of a service account on server endpoints.

```spl
index IN ("<SERVER_INDEX>") "<ACCOUNT>" host="<HOST>"
| table _time EventCode name ParentProcessName NewProcessName CommandLine
```

---

## Web / Proxy

### 8. Web data model – by user

Web traffic for one or more users from the CIM `Web` data model. URLs are defanged.

```spl
| tstats `summariesonly` max(_time) as _time values(Web.http_method) as http_method values(Web.status) as status count
    from datamodel=Web.Web
    where Web.user IN ("<USER>")
    by index, sourcetype, Web.user, Web.src, Web.dest, Web.url, Web.action, Web.http_referrer, Web.http_user_agent
| `drop_dm_object_name("Web")`
| eval url=replace(url, "\.", "[.]"), http_referrer=replace(http_referrer, "\.", "[.]")
| sort 0 - count
| fields _time index sourcetype user http_method status action src dest url http_referrer http_user_agent count
```

### 9. Web data model – by URL (identify clickers)

Finds who visited a malicious/suspicious URL or domain. Accepts a list of URLs/wildcards. Typical use: identify users who clicked a phishing link.

```spl
| tstats `summariesonly` max(_time) as _time values(Web.http_method) as http_method values(Web.status) as status count
    from datamodel=Web.Web
    where Web.url IN ("*<URL1>*", "*<URL2>*")
    by index, sourcetype, Web.user, Web.src, Web.dest, Web.url, Web.action, Web.http_referrer, Web.http_user_agent
| `drop_dm_object_name("Web")`
| eval url=replace(url, "\.", "[.]"), http_referrer=replace(http_referrer, "\.", "[.]")
| sort 0 - count
| fields _time index sourcetype user http_method status action src dest url http_referrer http_user_agent count
```

### 10. Proxy logs by host

Zscaler NSS web logs for a given device.

```spl
index IN ("web*", "proxy*") sourcetype=zscalernss-web devicehostname="<HOST>"
| table _time app action reason category hostname filename filetype http_method refererURL url
```

### 11. Proxy search by URL

Raw proxy search (outside the data model) that summarises first/last access and the proxy verdict per user.

```spl
index="*" url IN ("*<URL>*")
| eval Timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S.%3N")
| stats earliest(Timestamp) as earliest latest(Timestamp) as latest values(url) as url values(hostname) as hostname values(devicehostname) as devicehostname values(category) as category values(reason) as reason by action, user
```

---

## Phishing / Email

### 12. Emails containing a URL

Finds emails containing a given URL, excludes internal/security mailboxes and auto-replies, and outputs a defanged summary ready for the phishing dashboard.
Replace the example addresses in the exclusion lists with your own.

````spl
| tstats count earliest(_time) as earliest latest(_time) as latest
    values(All_Email.src) as src
    values(All_Email.return_addr) as return_addr
    values(All_Email.file_name) as file_name
    values(All_Email.url) as url
    FROM datamodel=Email
    WHERE ```CONDITIONS HERE```
        All_Email.url="*<URL>*"
        ```Exclusions below```
        AND NOT All_Email.src_user IN ("phishing@example.com", "support@example.zendesk.com", "information.security@example.com")
        AND NOT All_Email.recipient IN ("*@example-vendor.com", "phishing@example.com", "abuse@example-feeds.com")
        AND NOT All_Email.subject IN ("Automatic reply *")
    BY index, All_Email.src_user, All_Email.recipient, All_Email.subject, All_Email.action
| rename All_Email.* AS *, src_user AS EnvelopeSender
| convert timeformat="%d/%m/%y %H:%M:%S" ctime(earliest) ctime(latest)
| fillnull value="-" return_addr url file_name
| mvexpand url
| eval url=replace(url, "\.", "[.]")
| stats values(url) as url values(file_name) as file_name count by index, EnvelopeSender, action, recipient, subject, earliest, latest, src, return_addr
````

> The last three lines (`fillnull` → `stats`) are the workaround used by the phishing dashboard to defang URLs and keep rows with empty fields.

### 13. Proofpoint TAP – summary

Aggregates TAP events (delivered threats, clicks) per sender and event type.

```spl
index=email* sourcetype="*" *
| rename recipient{} as tmprecip, threatsInfoMap{}.threat as threat
| stats count
        values(fromAddress{}) as fromAddress
        values(headerFrom) as headerfrom
        values(eval(coalesce(recipient, tmprecip))) as recipient
        values(eval(coalesce(threat, url))) as Threat
        values(subject) as Subject
        values(userAgent) as userAgent
        by sender, eventType
| fields eventType fromAddress sender headerfrom Subject recipient Threat userAgent count
```

### 14. Proofpoint TAP – permitted clicks

Lists users who were allowed to click a URL (`clicksPermitted`), including the click IP and user agent.

```spl
index=email eventType=clicksPermitted url="*<URL>*"
| table _time recipient sender url clickIP userAgent
```

### 15. Attachment name pattern → hash

Finds attachments matching a file name pattern in email indexes and returns the file name together with its hash. Both multivalue fields (`file_name`, `file_hash`) are assumed to be position-aligned.

````spl
index=email* TERM("invoice") ```subset of events containing the keyword, for performance```
| search file_name="*invoice*acc*html" ```keep only events matching the pattern```
| eval pos=mvfind(file_name, ".*invoice.*acc.*html") ```position of the match in the file_name multivalue field```
| eval file=mvindex(file_name, pos), hash=mvindex(file_hash, pos) ```pick file name and hash at the same position```
| dedup hash ```remove duplicates```
| table file hash
````

---

## Network

### 16. Network traffic data model

Network connections from a source IP using the CIM `Network_Traffic` data model.

```spl
| tstats summariesonly=t count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src="<SRC_IP>"
    by _time, All_Traffic.user, All_Traffic.src, All_Traffic.dest, All_Traffic.transport, All_Traffic.action, All_Traffic.src_port, All_Traffic.dest_port, host, index, sourcetype
| rename All_Traffic.* as *
```

### 17. NAC search for rogue devices

Searches NAC (ForeScout) data for devices that look like rogue or offensive-security hardware: Raspberry Pi, Kali, Cobalt Strike-style hostnames, Commando VM, or devices in the "known bad" group. Remove the MAC filter if you only want the keyword/group matches.

```spl
index=<NAC_INDEX> sourcetype=<NAC_SOURCETYPE>
    (
        mac IN ("<MAC1>", "<MAC2>")
        OR host_properties.sw_hostname{}.value=*rasp*
        OR host_properties.dhcp_hostname_v2{}.value=*rasp*
        OR host_properties.vendor{}.value=*rasp*
        OR host_properties.dpl_os_classification{}.value=*rasp*
        OR host_properties.dpl_vendor_classification{}.value=*rasp*
        OR host_properties.mac_vendor_string{}.value=*rasp*
        OR host_properties.matched_fingerprints{}.value=*rasp*
        OR host_properties.os_classification{}.value=*rasp*
        OR host_properties.vendor_classification{}.value=*rasp*
        OR host_properties.sw_hostname{}.value=*kali*
        OR host_properties.dhcp_hostname_v2{}.value=*kali*
        OR host_properties.sw_hostname{}.value=*strike*
        OR host_properties.dhcp_hostname_v2{}.value=*strike*
        OR host_properties.sw_hostname{}.value=*<HOSTNAME_PATTERN>*
        OR host_properties.dhcp_hostname_v2{}.value=*<HOSTNAME_PATTERN>*
        OR host_properties.sw_hostname{}.value=*commando*
        OR host_properties.dhcp_hostname_v2{}.value=*commando*
        OR host_properties.in_group{}.value="<ORG> Policy Groups,Dashboard,Non Corporate Hosts,Core Discovery Groups,Linux/Unix,All Non-Corporate Devices (Known Bad)"
    )
| rename host_properties.adm{}.value as action, host_properties.sw_port_vlan_name{}.value as vlan
| stats values(host_properties.sw_hostname{}.value) as swHostname
        values(host_properties.dhcp_hostname_v2{}.value) as dhcpHostname
        values(host_properties.sw_location{}.value) as swLocation
        values(host_properties.segment_path{}.value) as segmentPath
        earliest(_time) as earliestEvent latest(_time) as latestEvent count
        by mac, vlan, ip, action
| convert ctime(earliestEvent) ctime(latestEvent)
```

---

## Enrichment

### 18. Asset lookup – bulk IPs

Enriches a list of IP addresses with asset information: owner team, OS, patch status, server role and support queue.

```spl
| inputlookup asset_lookup
| search calc_ips IN ("<IP1>", "<IP2>") service_queue="*" calc_tag="*" lookup_asset_type="*" calc_domain="*" calc_os="*" lookup_region="*" lookup_asset_type_flag="*" decomm_flag="0"
| table hostname calc_ips lookup_asset_type calc_last_seen calc_os calc_domain calc_last_patch_date calc_needs_patching calc_last_patch_description calc_country calc_model service_server_role service_system service_used_by service_queue service_team_name service_tier
```

### 19. Identity lookup – bulk users

Two ways to pull identity details (manager, department, etc.) for users.

**a) Directly from the identity lookup (bulk):**

```spl
| inputlookup identity_lookup_expanded
| search identity IN ("<USER1>", "<USER2>")
```

**b) Using the ES identity macro (single user):**

```spl
| makeresults
| eval user="<USER>"
| `get_identity4events(user)`
```

---

## Cloud

### 20. AWS GuardDuty network traffic stats

Aggregation tail for GuardDuty network-connection findings. Append it to your GuardDuty base search.

```spl
| stats values(detail.service.eventFirstSeen) as FirstSeen
        values(detail.service.eventLastSeen) as LastSeen
        values(instanceType) as instanceType
        count
        values(threat_type) as threat_type
        values(description) as description
        values(ResourceTypeAffected) as ResourceTypeAffected
        values(connectionDirection) as connectionDirection
        values(src_ip) as src_ip
        values(detail.service.action.networkConnectionAction.localPortDetails.port) as src_port
        values(dest) as dest
        values(detail.service.action.networkConnectionAction.remotePortDetails.port) as dest_port
        values(action) as action
        by accountId, index, sourcetype
```

### 21. Azure resource activity

Azure resource operations (who did what, from which IP) newest first.

```spl
index="azure_resource" object="<OBJECT>"
| table _time Subscription category user callerIpAddress user_type command dest level properties.message object resultType
| sort 0 - _time
```

---

## Utilities

### 22. Find indexes containing a string

Discovers which indexes and sourcetypes contain a given string (IOC, hostname, username). `TERM()` keeps it fast; the string must be a whole indexed term.

```spl
index=* index!=core_splunk_internal TERM("<STRING>")
| stats count by index, sourcetype
| sort 0 - count
```

### 23. Snippet: defang URLs

Append to any query that outputs a `url` field.

```spl
| eval url=replace(url, "\.", "[.]")
```

### 24. Snippet: first/last event time

Append to any search to get the time range of the results in readable format.

```spl
| stats earliest(_time) as earliestEvent latest(_time) as latestEvent
| convert ctime(earliestEvent) ctime(latestEvent)
```

---

## Disclaimer

Queries are provided as-is for defensive security / incident response work. Test in your own environment before relying on them.
