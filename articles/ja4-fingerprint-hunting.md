> **Sanitized walkthrough.** This follows the method I used on a distributed attack against a web application firewall (WAF), rewritten with invented numbers, addresses and fingerprints. JA4 values shown here are illustrative placeholders, not those of any real tool. No employer data is included.

## 1. The problem

A public login and search application sat behind a WAF. Traffic doubled, then tripled, and the usual controls stopped helping:

- **Per-IP rate limits did nothing.** About 38,000 source IPs each sent only a few requests.
- **User-Agent blocking did nothing.** The traffic rotated through dozens of realistic browser strings.
- **Geo blocking was too blunt.** Sources spanned 100+ networks, many of them residential or cloud addresses.

Everything an attacker can change cheaply (IP, User-Agent, headers) was changing. What they can't change cheaply is the way their TLS library builds the ClientHello. That is what JA4 fingerprints.

## 2. What JA4 is

JA4 is a readable fingerprint of a TLS ClientHello. It was designed to fix a weakness in JA3: modern browsers randomize the order of TLS extensions, so one browser produced many JA3 hashes. JA4 sorts the cipher suites and extensions before hashing, so the same client yields the same fingerprint.

Anatomy of an illustrative value, `t13d1209h1_3f9c1a5be2d4_7c20e8b1a9f3`:

| Part | Example | Meaning |
|---|---|---|
| Protocol | `t` | TCP (`q` = QUIC, `d` = DTLS) |
| TLS version | `13` | Highest version offered |
| SNI | `d` | Domain present in SNI (`i` = no SNI / IP) |
| Cipher count | `12` | Number of cipher suites offered |
| Extension count | `09` | Number of extensions offered |
| ALPN | `h1` | First and last character of the first ALPN value (`h2`, `h1`, `00` = none) |
| Hash b | `3f9c1a5be2d4` | Truncated SHA-256 of the sorted cipher suites |
| Hash c | `7c20e8b1a9f3` | Truncated SHA-256 of the sorted extensions plus signature algorithms |

GREASE values are ignored. Because the first section is human-readable, you can hunt on **patterns** (for example, "TLS 1.3, no ALPN, few extensions") and not only on exact hashes.

### The JA4+ family

| Fingerprint | Based on | Useful for |
|---|---|---|
| **JA4** | TLS client hello | Identifying the client library / tool |
| **JA4S** | TLS server hello | Fingerprinting servers and C2 infrastructure |
| **JA4H** | HTTP request (method, version, header order, cookies, language) | Separating tools that share a TLS stack |
| **JA4T** | TCP options and window size | Spotting OS or spoofed stacks |
| **JA4X** | X.509 certificate structure | Clustering certificates from the same generator |
| **JA4L** | Latency between hops | Estimating distance, spotting proxies |

JA4 itself is open. Several of the other JA4+ methods use a different licence, so check terms before building them into a product.

## 3. Where you can see it

JA4 is computed where the TLS handshake is visible:

- **WAF / CDN / load balancer** that terminates TLS. Several vendors now expose JA3/JA4 in rules and logs; check yours.
- **Zeek** with the JA4 package, which adds JA4 fields to its logs.
- **Suricata** and **Wireshark/tshark** in recent versions.

Important limit: if a CDN terminates TLS, your origin sees the **CDN's** fingerprint, not the client's. Collect it at the edge.

```
# Check whether your tshark build knows JA4 fields
tshark -G fields | grep -i ja4

# Stack client fingerprints from a capture
tshark -r edge.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.handshake.ja4 \
  | sort | uniq -c | sort -rn | head -20
```

```
# Zeek: field names depend on package version, check your log header first
zeek-cut id.orig_h ja4 < ssl.log | sort | uniq -c | sort -rn | head
```

## 4. Hunting workflow

### Step 1: Establish the baseline
Before the attack, your site has a normal mix: a few popular browser fingerprints, mobile apps, a handful of known bots and monitoring tools. Record the top 20 JA4 values by request count over 30 days. Without this, "unusual" has no meaning.

### Step 2: Stack by JA4 during the incident
For each fingerprint, count requests, **distinct IPs**, distinct ASNs and distinct User-Agents. The signal is a fingerprint with huge IP diversity and low per-IP volume that is rare or new in your baseline.

**Splunk** (adapt field names to your WAF log):
```
index=waf earliest=-1h
| stats count as requests dc(src_ip) as ips dc(asn) as asns dc(http_user_agent) as user_agents
        values(uri_path) as paths by ja4
| eval req_per_ip=round(requests/ips,1)
| sort - requests
```

**Sentinel / KQL:**
```
WafLogs
| where TimeGenerated > ago(1h)
| summarize Requests=count(), IPs=dcount(ClientIP), ASNs=dcount(ClientASN),
            UAs=dcount(UserAgent), Paths=make_set(UriPath, 5) by Ja4
| extend ReqPerIP = round(todouble(Requests)/IPs, 1)
| order by Requests desc
```

Illustrative result:

| JA4 | Requests | IPs | ASNs | User-Agents | Req/IP |
|---|---|---|---|---|---|
| `t13d1209h1_3f9c1a5be2d4_7c20e8b1a9f3` | 412,000 | 38,100 | 118 | **47** | 10.8 |
| `t13d1516h2_...` (mainstream browser) | 96,000 | 41,000 | 2,100 | 310 | 2.3 |
| `t13d1517h2_...` (mobile browser) | 31,000 | 12,000 | 640 | 95 | 2.6 |

One fingerprint produced about 70% of requests while claiming 47 different browsers. A real browser build reports one family of User-Agents. That mismatch is the finding.

### Step 3: Find when it first appeared
```
index=waf earliest=-30d
| stats min(_time) as first_seen max(_time) as last_seen dc(src_ip) as ips by ja4
| where first_seen > relative_time(now(), "-2h")
| sort - ips
```
A fingerprint that did not exist yesterday and has 38,000 IPs today is not organic.

### Step 4: Corroborate with other layers
One signal is a lead. Several agreeing signals are a conclusion.

| Check | What agreement looks like |
|---|---|
| **JA4H** | Identical header order and count across all the "different" browsers |
| **User-Agent vs JA4** | Chrome UA with a non-Chrome JA4 |
| **Headers** | Missing `Accept-Language`, cookies, or `Referer` that real browsers send |
| **Behavior** | Same path sequence, no asset loads (no CSS/JS/images), fixed timing |
| **JA4T** | TCP options inconsistent with the claimed OS |
| **Sources** | Hosting, proxy or residential-proxy ASNs, not ordinary ISPs |

### Step 5: Enrich the IPs
Pivot a sample (not all 38,000) through threat intelligence: VirusTotal / Google Threat Intelligence, AbuseIPDB, GreyNoise. Look at the share of addresses with prior reports, hosting versus residential ranges, and how long each address has been seen. Use the [IOC checker](intel.html) on this site to open the pivots quickly. Also search your intel platform or JA4 databases for the fingerprint, since a match can name the tool or library.

### Step 6: Look back
Run the same fingerprint over 30 to 90 days of history and across other applications. Earlier low-volume use of the same JA4 often reveals reconnaissance or credential-stuffing tests that preceded the visible attack.

## 5. Mitigation

Don't block on JA4 alone. Combine it with context so you catch the tool and spare legitimate users.

| Control | Example logic |
|---|---|
| **Targeted block / challenge** | JA4 = attack value **and** path in (`/login`, `/search`) |
| **Fingerprint-aware rate limit** | Count requests per JA4 instead of per IP |
| **Mismatch rule** | UA claims Chrome **and** JA4 is not a known Chrome fingerprint |
| **Challenge before block** | Serve a challenge first and watch the pass rate; a bot tool usually fails it |
| **Alerting** | New JA4 with more than N distinct IPs inside 10 minutes |

Rate limiting by fingerprint is the key move here. The attack stayed under every per-IP threshold, but it could not hide from a limit applied to the single fingerprint they all shared.

## 6. Limits and false positives

- **Shared fingerprints.** Many legitimate clients share one JA4: every copy of a browser version, `curl`, Python `requests`, Go programs, monitoring agents, mobile SDKs. A popular fingerprint tells you the *library*, not the *intent*.
- **Attackers adapt.** Tools exist that imitate a browser's ClientHello. A cheap commodity tool is easy to fingerprint, a careful one is not. That is why you corroborate with JA4H, JA4T and behavior.
- **Proxies and CDNs** change what you observe.
- **A fingerprint is not attribution.** It links traffic to a client implementation. It does not tell you who is behind it.
- **Review the collateral damage.** After a rule goes live, check how many blocked requests also carried valid sessions or known-good users.

Treat JA4 as a **clustering key**: it turns 38,000 apparent strangers into one actor you can reason about, rate limit and track.

## 7. Report summary

| Item | Finding |
|---|---|
| Attack type | Distributed application-layer attack on login and search endpoints |
| Evasion | IP rotation, 47 rotating User-Agents, low per-IP volume |
| Pivot that worked | One JA4 shared by ~70% of requests, first seen the same hour |
| Corroboration | Identical JA4H, no asset requests, hosting-heavy ASNs |
| Mitigation | JA4 + path rule, per-fingerprint rate limit, challenge |
| Follow-up | 90-day lookback, new-fingerprint alert, JA4 added to the baseline dashboard |

## 8. Key takeaways

1. When IP and User-Agent are rotating, hunt on what the attacker can't easily rotate: the TLS client.
2. Stack by fingerprint, then count **distinct IPs per fingerprint**. Low volume per IP with huge IP diversity is the signature of a distributed tool.
3. Corroborate with JA4H and behavior before you act.
4. Apply controls to the fingerprint combined with path and rate, and measure collateral damage.
5. Record the baseline *before* you need it.
