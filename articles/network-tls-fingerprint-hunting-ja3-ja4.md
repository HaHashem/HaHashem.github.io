> **Lab scenario and templates.** Hosts, addresses, fingerprints and numbers below are invented (IPs from documentation ranges, JA3/JA4 values are illustrative placeholders). The Splunk queries are templates: sourcetype and field names depend on how your network logs are ingested. Test them on a short time range first. No employer data is included.

## 1. What is a TLS fingerprint?

When a client starts a TLS connection, its first message, the **ClientHello**, lists what it supports: TLS versions, cipher suites, extensions, supported groups (curves), signature algorithms and application protocols. That message is sent **in the clear**, before encryption starts. In TLS 1.3 the handshake is mostly encrypted after the ClientHello, but the ClientHello itself is still visible unless Encrypted Client Hello (ECH) is used.

Different software builds the ClientHello differently. Chrome, Firefox, `curl`, Python `requests`, Go programs, .NET and a malware family's custom code each produce a recognizable pattern. A **TLS fingerprint** boils that pattern down to a short value you can count, group and search, **without decrypting anything**.

That makes it useful for network defense: you can see *what kind of client* is talking, even when IP addresses, domains and User-Agents change.

## 2. JA3: the original

**JA3** was published by Salesforce researchers in 2017. It takes five parts of the ClientHello, in the order they appear:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```
Values within a field are joined with `-`, fields with `,`, GREASE values are dropped, and the string is hashed with **MD5**, giving a 32-character value such as `e7d705a3286e19ea42f587b344ee6865`. The server-side partner, **JA3S**, does the same for the ServerHello.

Strengths: simple, widely supported in Zeek, Suricata, Wireshark, firewalls and intel feeds.

Weaknesses:
- It is **order-sensitive**. Since browsers began randomizing the order of TLS extensions, one browser can produce many JA3 values, which breaks matching.
- An MD5 hash is **opaque**. You cannot tell what a value means without a lookup.
- It does not cover ALPN or signature algorithms, and it was designed for TLS over TCP.

> **Naming note.** The "3" in JA3 is part of the name, not a TLS version. TLS 1.3 is a protocol version. JA4 records it in the fingerprint as `13`. If you see references to a "v3" TLS fingerprint, they almost always mean JA3.

## 3. JA4: the successor

**JA4** was published by FoxIO in 2023, designed to fix those problems. Instead of one opaque hash, it is a three-part, **human-readable** value:

```
t13d1516h2_8daaf6152771_02713d6af862
 a            b             c
```

| Part | Example | Meaning |
|---|---|---|
| **a** | `t13d1516h2` | `t` = TCP (`q` = QUIC, `d` = DTLS) · `13` = TLS 1.3 · `d` = SNI is a domain (`i` = no SNI or an IP) · `15` = 15 cipher suites · `16` = 16 extensions · `h2` = first ALPN value is HTTP/2 |
| **b** | `8daaf6152771` | Truncated SHA-256 of the **sorted** cipher suites |
| **c** | `02713d6af862` | Truncated SHA-256 of the **sorted** extensions plus signature algorithms |

Because ciphers and extensions are **sorted before hashing**, randomized extension order no longer changes the result. Because part `a` is readable, you can hunt on **patterns** ("TLS 1.3 clients with no ALPN and few extensions") and not only on exact values.

JA4 belongs to a family called **JA4+**: JA4S (server), JA4H (HTTP request), JA4X (X.509 certificate), JA4T (TCP), JA4L (latency) and others. The core JA4 method is open. Some other JA4+ methods use a different licence, so check terms before embedding them in a product.

## 4. JA3 versus JA4

| | JA3 | JA4 |
|---|---|---|
| Published | 2017, Salesforce | 2023, FoxIO |
| Format | 32-character MD5, opaque | `a_b_c`, readable, with a readable prefix |
| Field order | Order-sensitive (as seen on the wire) | Sorted, so stable |
| Browsers that randomize extensions | Many values for one browser | One stable value |
| Protocols | TLS over TCP | TCP, **QUIC** and DTLS |
| What it covers | Version, ciphers, extensions, curves, point formats | Version, SNI type, counts, ALPN, ciphers, extensions, signature algorithms. It does **not** hash the curve values |
| Partial matching | No: exact hash only | Yes: match on part `a`, or on `b` or `c` alone |
| Ecosystem | Very widely supported, big historical lists | Newer, growing quickly |

**In practice, keep both.** JA3 has years of intel and legacy tooling behind it. JA4 is more robust against modern clients and easier to read. If your sensors can log both, do.

## 5. Where to capture it

You can only fingerprint the handshake where you can see it:

- **Zeek:** packages add `ja3`, `ja3s` and `ja4` fields to `ssl.log`. Field names depend on the package, so check your log header.
- **Suricata:** can log JA3, JA3S and, in recent versions, JA4, in its `tls` events.
- **tshark / Wireshark:**
  ```
  tshark -r capture.pcapng -Y "tls.handshake.type == 1" \
    -T fields -e ip.src -e ip.dst -e tls.handshake.ja3 -e tls.handshake.ja4
  ```
  Check your build with `tshark -G fields | grep -i ja`.
- **WAF, CDN and some firewalls** expose JA3 or JA4 in logs and rules. Check what your vendor provides.

Limits: a proxy or CDN that terminates TLS means you see **its** fingerprint, not the client's. ECH can hide the SNI. Fingerprints identify a **client implementation**, not a person or a verdict.

## 6. Hunting in Splunk

The examples assume Zeek `ssl` logs in Splunk with fields `id.orig_h` (source), `id.resp_h` (destination), `server_name` (SNI), `ja3` and `ja4`. Adjust the index and sourcetype names to your environment. Suricata users can use `tls.ja3.hash` and `tls.ja4` fields in the same way.

### 6.1 Stack fingerprints: what clients exist in my network?
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| stats count dc(id.orig_h) as hosts dc(server_name) as sni_count values(server_name) as sample_sni by ja4
| sort - hosts
```
Do the same for `ja3`. Your baseline will show a handful of high-count fingerprints (browsers, OS update agents, standard apps) and a long tail. **The long tail is where hunting happens.**

### 6.2 New fingerprints: first seen recently, on few hosts
```
index=zeek sourcetype=zeek_ssl earliest=-30d
| stats min(_time) as first_seen count dc(id.orig_h) as hosts values(id.orig_h) as src by ja4
| where hosts<=2 AND first_seen>relative_time(now(), "-1d")
| convert ctime(first_seen)
| sort - count
```
A fingerprint that did not exist yesterday and appears on one workstation may be new software, or a new implant.

### 6.3 Pivot from a fingerprint to the hosts and IPs behind it
You found a suspicious fingerprint. Who uses it, and where does it connect?
```
index=zeek sourcetype=zeek_ssl ja4="t13d1209h1_3f9c1a5be2d4_7c20e8b1a9f3"
| stats count min(_time) as first max(_time) as last values(server_name) as sni by id.orig_h, id.resp_h
| convert ctime(first) ctime(last)
| sort - count
```
- The **`id.orig_h`** column is your list of affected hosts. Map them to owners with your asset or DHCP lookup.
- The **`id.resp_h`** column is the infrastructure to investigate.
- If only one or two internal hosts use it and all go to the same rare destination, that's a lead.

### 6.4 Fingerprint versus claimed identity
A User-Agent says "Chrome" but the TLS fingerprint isn't Chrome's. Build a lookup file `known_chrome_ja4.csv` (columns `ja4,label`) from your baseline of confirmed browser traffic, then:
```
index=proxy earliest=-24h http_user_agent="*Chrome*"
| lookup known_chrome_ja4.csv ja4 OUTPUT label
| where isnull(label)
| stats count dc(src_ip) as hosts values(dest_host) as destinations by ja4, http_user_agent
| sort - count
```
This requires the JA4 to be present in your proxy or gateway logs. It catches tools that fake a browser User-Agent but use a non-browser TLS stack.

### 6.5 Beaconing: regular connections from one host to one destination
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| sort 0 id.orig_h id.resp_h _time
| streamstats current=f last(_time) as prev by id.orig_h id.resp_h
| eval delta=_time-prev
| stats count avg(delta) as avg_s stdev(delta) as sd_s values(ja4) as ja4 values(server_name) as sni by id.orig_h, id.resp_h
| eval jitter=round(sd_s/avg_s, 2)
| where count>50 AND jitter<0.2
| sort - count
```
Low `jitter` (regular timing) with many connections to one destination suggests automation. Software updaters and monitoring agents also beacon, so check the fingerprint and SNI before escalating.

### 6.6 Rare external destinations (IPs and hosts)
Fingerprints are one lens. Destinations are another:
```
index=firewall action=allowed dest_port=443 earliest=-30d
| where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip))
| stats min(_time) as first_seen dc(src_ip) as hosts sum(bytes_out) as bytes_out by dest_ip
| where first_seen>relative_time(now(), "-1d") AND hosts<=2
| convert ctime(first_seen)
| sort - bytes_out
```
New external destinations contacted by one or two hosts, ordered by how much data left, is a short and useful list.

### 6.7 Match against indicator lists
```
index=zeek sourcetype=zeek_ssl earliest=-7d
| lookup ioc_ips.csv ip AS id.resp_h OUTPUT source AS ioc_source
| lookup ioc_ja4.csv ja4 OUTPUT source AS ja4_source
| where isnotnull(ioc_source) OR isnotnull(ja4_source)
| stats count min(_time) as first by id.orig_h, id.resp_h, server_name, ja4, ioc_source, ja4_source
```
Keep lookups current and record where each indicator came from.

### 6.8 Servers: JA4S and certificates
Server fingerprints help spot command-and-control infrastructure that shares a configuration:
```
index=zeek sourcetype=zeek_ssl earliest=-30d
| stats dc(id.orig_h) as clients values(server_name) as sni by id.resp_h, ja4s
| where clients<=3
```
Several unrelated external IPs sharing one rare `ja4s` can indicate infrastructure built the same way. Treat it as a lead and confirm with other evidence.

## 7. Worked example (synthetic)

**Step 1: baseline.** 6.1 shows 142 fingerprints. The top eight are browsers, OS updaters and a corporate VPN client. The rest are a long tail.

**Step 2: new on few hosts.** 6.2 returns one fingerprint:

| JA4 | Hosts | First seen | Sample SNI |
|---|---|---|---|
| `t13d1209h1_3f9c1a5be2d4_7c20e8b1a9f3` | 1 (`WS-031`) | today 13:21 | `cdn-verify[.]example` |

Reading part `a`: TLS 1.3, SNI present, 12 ciphers, 9 extensions, ALPN `h1`. That is a small, simple client, unlike a modern browser's larger list with `h2`.

**Step 3: pivot.** 6.3 shows `WS-031` connecting to `203.0.113.77` and `198.51.100.23`, with a regular 60-second pattern from 6.5 (jitter 0.04).

**Step 4: destination check.** 6.6 shows both IPs are new, and `198.51.100.23` received about 6 MB from the host.

**Step 5: corroborate.** Endpoint telemetry shows PowerShell wrote `svc_update.exe` shortly before. The fingerprint is therefore the implant's TLS stack, and any other host using it is suspect. 6.2 and 6.3 over 30 days found no other host.

**Conclusion:** one infected workstation, with a command channel and a data upload. The fingerprint, IPs and SNI are added to the watchlist.

## 8. Limits and false positives

- **Shared fingerprints.** A fingerprint identifies the library. Many programs share one, so common values prove little. Rare values prove little too, until corroborated.
- **Impersonation.** Tools exist that copy a browser's ClientHello. Combine fingerprints with timing, destinations, SNI, certificates and endpoint evidence.
- **Visibility.** TLS-terminating proxies and CDNs change what you see, and ECH can hide SNI.
- **Baseline first.** Without 30 days of normal, "rare" and "new" are guesses. Build and refresh the baseline.
- **Not attribution.** A fingerprint links traffic to a client implementation, not to a threat actor.

## 9. Key takeaways

1. A TLS fingerprint describes **how a client builds its handshake**, visible without decrypting.
2. **JA3** is the original: an MD5 of ordered fields, widely supported, but broken by extension randomization.
3. **JA4** is the successor: readable, sorted, covers ALPN, QUIC and SNI type, and allows partial matching. Use both if you can.
4. In Splunk, **stack, find new and rare, pivot to hosts and IPs, check beaconing, and match against indicators**.
5. Always corroborate with destinations, timing and endpoint data, and keep a baseline.
