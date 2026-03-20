#!/usr/bin/env python3
"""DNS performance benchmark — compares Numa against public resolvers."""

import subprocess
import sys
import re
import statistics
import json

NUMA_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15353
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 20
DOMAINS = [
    "google.com", "github.com", "amazon.com", "cloudflare.com",
    "reddit.com", "stackoverflow.com", "rust-lang.org", "wikipedia.org",
    "netflix.com", "twitter.com",
]

RESOLVERS = [
    ("Numa(cold)",   "127.0.0.1", NUMA_PORT),
    ("Numa(cached)", "127.0.0.1", NUMA_PORT),
    ("System",       "",           53),
]

# Detect system resolver
try:
    out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True)
    m = re.search(r"nameserver\[0\]\s*:\s*([\d.]+)", out.stdout)
    if m:
        RESOLVERS[2] = ("System", m.group(1), 53)
except Exception:
    pass

# Add public resolvers — skip if unreachable
for name, ip in [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Quad9", "9.9.9.9")]:
    try:
        out = subprocess.run(
            ["dig", f"@{ip}", "example.com", "+short", "+time=2", "+tries=1"],
            capture_output=True, text=True, timeout=4
        )
        if out.stdout.strip():
            RESOLVERS.append((name, ip, 53))
    except Exception:
        pass

A = "\033[38;2;192;98;58m"
T = "\033[38;2;107;124;78m"
D = "\033[38;2;163;152;136m"
B = "\033[1m"
R = "\033[0m"


def query_ms(server, port, domain):
    try:
        out = subprocess.run(
            ["dig", f"@{server}", "-p", str(port), domain,
             "+noall", "+stats", "+tries=1", "+time=3"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"Query time:\s+(\d+)\s+msec", out.stdout)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def flush_cache(domain=None):
    try:
        url = f"http://localhost:5380/cache/{domain}" if domain else "http://localhost:5380/cache"
        subprocess.run(["curl", "-s", "-X", "DELETE", url],
                       capture_output=True, timeout=3)
    except Exception:
        pass


print()
print(f"{A}  ╔══════════════════════════════════════════════════════════╗{R}")
print(f"{A}  ║{R}  {B}{A}NUMA{R}  DNS Performance Benchmark                       {A}║{R}")
print(f"{A}  ╚══════════════════════════════════════════════════════════╝{R}")
print()
print(f"{D}  Domains: {len(DOMAINS)} | Rounds: {ROUNDS} | Total: {len(DOMAINS) * ROUNDS} queries per resolver{R}")
print()

results = {}

for name, server, port in RESOLVERS:
    print(f"  {T}Testing{R} {B}{name}{R}...", end="", flush=True)

    if name == "Numa(cold)":
        flush_cache()

    latencies = []
    for r in range(ROUNDS):
        for domain in DOMAINS:
            if name == "Numa(cold)":
                flush_cache(domain)
            ms = query_ms(server, port, domain)
            if ms is not None:
                latencies.append(ms)

    if latencies:
        latencies.sort()
        n = len(latencies)
        results[name] = {
            "avg": round(statistics.mean(latencies), 1),
            "p50": latencies[n // 2],
            "p99": latencies[int(n * 0.99)],
            "min": min(latencies),
            "max": max(latencies),
            "count": n,
        }
    print(f" {D}done ({len(latencies)} queries){R}")

print()
print(f"{A}  ┌──────────────┬────────┬────────┬────────┬────────┬────────┐{R}")
print(f"{A}  │{R} {B}Resolver{R}     {A}│{R} {B}Avg{R}    {A}│{R} {B}P50{R}    {A}│{R} {B}P99{R}    {A}│{R} {B}Min{R}    {A}│{R} {B}Max{R}    {A}│{R}")
print(f"{A}  ├──────────────┼────────┼────────┼────────┼────────┼────────┤{R}")

for name, _, _ in RESOLVERS:
    if name not in results:
        continue
    r = results[name]
    if "cached" in name.lower():
        c = T
    elif "cold" in name.lower():
        c = A
    else:
        c = D
    print(f"{c}  │ {name:<12s} │ {r['avg']:5.1f}ms │ {r['p50']:4d}ms │ {r['p99']:4d}ms │ {r['min']:4d}ms │ {r['max']:4d}ms │{R}")

print(f"{A}  └──────────────┴────────┴────────┴────────┴────────┴────────┘{R}")

# Summary comparison
cached = results.get("Numa(cached)", {})
cold = results.get("Numa(cold)", {})

print()
if cached and cached["avg"] > 0:
    for name in [n for n, _, _ in RESOLVERS if n not in ("Numa(cold)", "Numa(cached)")]:
        other = results.get(name, {})
        if other and other["avg"] > 0:
            x = other["avg"] / max(cached["avg"], 0.1)
            print(f"  {T}Numa cached is ~{x:.0f}x faster than {name} (avg){R}")
    if cold and cold["avg"] > 0:
        x = cold["avg"] / max(cached["avg"], 0.1)
        print(f"  {T}Numa cached is ~{x:.0f}x faster than Numa cold (avg){R}")

# Save raw results as JSON
out_path = "bench/results.json"
with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  {D}Raw results saved to {out_path}{R}")
print()
