---
title: "SQL Injection: Confirm the Differential Before You Extract"
date: 2026-09-26 11:06:00 +0700
categories:
  - notes
tags:
  - sqli
  - injection
  - detection
  - web
  - methodology
---

The instinct with SQL injection is to drop a quote and look for an error. That is the weakest signal available. Errors get suppressed, genericized, or caught by a WAF before your request ever reaches the database. The reliable signal is not an error. It is a differential: the same request with a true condition and a false condition behaving differently, repeatably.

This note is about confirming the injection before extracting anything. Same discipline as the SSRF series. Claims no stronger than the evidence.

## Enumerate surfaces before payloads

You cannot test what you have not listed. Before touching a payload, collect the parameters in scope. Query string, body, JSON fields, cookies, and headers all carry input.

```bash
# from an exported HTTP history (one request line per entry)
grep -oE '(GET|POST) [^ ]+' history.txt | awk '{print $2}' | sort -u

# naive parameter list
grep -oE '[?&][a-zA-Z0-9_]+=' history.txt | sed 's/^[?&]//; s/=$//' | sort -u
```

That gives you a target list, not a finding. Sort it by likelihood: numeric ids, filter and sort parameters, and anything that feeds a `WHERE` clause by name (`id=`, `user=`, `category=`, `order=`). Those are the ones worth your time first.

## The boolean differential

This is the core method. Pick one parameter and send two requests that differ only in a truth value. Everything else stays byte-identical.

```bash
for c in '1 AND 1=1' '1 AND 1=2'; do
  curl -s -o /tmp/body -w "%{http_code} %{size_download}\n" \
    --data-urlencode "id=$c" "https://target.example/api/items"
done
```

If `1 AND 1=1` and `1 AND 1=2` return a different body size, status, or visible content, you have a candidate. The keyword is candidate, not finding, because a single difference can come from something other than the database.

The test that makes it real is consistency:

- repeat each request three times and confirm the split is stable
- swap the base value (`id=1` becomes `id=2`) and confirm the split survives, so it is not one specific row
- change the truth pair to something unrelated to the original query, `AND 2>1` against `AND 1>2`, so you are not accidentally matching existing data

If the split holds across all three, the parameter is affecting the parse tree, which is what injection means.

## When the body does not move

Plenty of applications swallow the result and return the same page regardless. The output channel is closed, but the timing channel is usually open. A conditional sleep turns the truth value into a measurable delay.

```bash
for c in "1);SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--" \
         "1);SELECT CASE WHEN (1=2) THEN pg_sleep(3) ELSE pg_sleep(0) END--"; do
  curl -s -o /dev/null -w "%{time_total}\n" \
    --data-urlencode "id=$c" "https://target.example/api/items"
done
```

Two things keep this honest. First, timing is noisy, so run each payload three times and look for a separation clearly larger than the jitter, not one lucky slow response. Second, the sleep function is DBMS-specific: MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`. If the wrong one is used, the query errors and you learn nothing.

## False positives to rule out before you write anything up

Three things mimic injection and waste everyone's time.

- **WAF behavior.** A block page returned for the true payload but not the false one looks like a differential. Confirm by sending a benign keyword the WAF also flags, or by changing only the encoding. If the block tracks the keyword rather than the logic, it is the WAF, not the database.
- **Generic error handling.** If any malformed value returns an error page, then the error is about input shape, not SQL logic. Test with a syntactically broken but non-SQL value and see if it produces the same response.
- **Caching.** A cached response can freeze one side of your pair. Add a unique cache-buster parameter to every request and repeat.

Each of these produces a difference. None of them produces a database.

## Read the DBMS from behavior, not error text

Error strings are frequently scrubbed, and when they are not, they are a gift you should not depend on. You can usually fingerprint the engine through the same differential, using syntax that parses on one engine and errors on another, or concatenation behavior that differs between them. Keep every probe read-only. The point is to know what you are talking to, not to pull data yet.

## Extraction discipline

Once injection is confirmed, the goal is to demonstrate impact, not to copy the database. Pull the minimum that proves the finding and stop.

```bash
sqlmap -u 'https://target.example/api/items?id=1' \
  --batch --level=3 --risk=2 \
  --technique=BT \
  --current-user --current-db --banner
```

`--technique=BT` limits it to boolean and time based, the two channels you already proved. Avoid stacked-query and heavy union techniques unless scope allows them, because they change the risk profile of the request. Do not run `--dump` against production. sqlmap is loud and will trip a WAF, so scope it to the engagement window and the authorized host.

Current user, current database, and version are enough to establish impact. Everything past that is a decision for the client, not for your terminal.

## The fix, with a proof command

The control is parameterization, not escaping. Escaping is a filter and filters lose to encoding. A parameterized query sends the value as data, so the input can never change the parse tree.

```python
# psycopg, the value is bound, not concatenated
cur.execute("SELECT id, name FROM items WHERE id = %s", (item_id,))
```

The test that proves the control holds is to send a value that would be a payload if it were concatenated, and show it is treated as data:

```bash
# must return zero rows or a normal empty result, never an error, never all rows
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://target.example/api/items?id=1'%20OR%20'1'='1"
```

Alongside that:

- run the application under a least-privilege database user, no stacked queries, no filesystem or `xp_cmdshell` privileges
- never build identifiers from user input; `ORDER BY` and table names cannot be parameterized, so they need a strict allowlist
- log the query shape, not the raw value, so you can alert on parse-tree changes

A single control you can prove beats a checklist you cannot.

## Closing

The claim is only as strong as the differential you can reproduce. One true and false pair, repeated, with the confounds ruled out and the engine identified, is a finding. A single error string is a hypothesis.

Same rule as the rest of this series: hand someone the commands, and let them get the same result you did.