"""
Orchestrator — invokes Lambda in parallel for all 343K NICENIC domains.
Run locally; Lambda does the actual HTTP work.

Usage:
    pip install boto3
    aws configure  (or set AWS_* env vars)
    python scan/invoke_all.py --function nicenic-http-scan --input 3765_full.csv
    python scan/invoke_all.py --function nicenic-http-scan --input 3765_full.csv --resume --out data/lambda_results.jsonl
"""

import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import boto3
except ImportError:
    print("[!] pip install boto3")
    sys.exit(1)

BATCH_SIZE   = 800   # domains per Lambda invocation
MAX_PARALLEL = 80    # concurrent Lambda invocations


def load_domains(csv_path: Path) -> list[str]:
    csv.field_size_limit(1_000_000)
    domains = []
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            d = (row.get("url") or row.get("domain","")).strip().lower()
            d = re.sub(r"^https?://", "", d).strip("/")
            if d:
                domains.append(d)
    return domains


def load_done(jsonl_path: Path) -> set[str]:
    done = set()
    if not jsonl_path.exists():
        return done
    with open(jsonl_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                done.add(json.loads(line)["domain"])
            except Exception:
                pass
    print(f"  [resume] {len(done)} already done")
    return done


def invoke_batch(client, function_name: str, batch: list[str], batch_id: int) -> list[dict]:
    payload = json.dumps({"domains": batch, "batch_id": batch_id}).encode()
    resp = client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=payload,
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        print(f"  [error] batch {batch_id}: {body}")
        return []
    return body.get("results", [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--function", required=True, help="Lambda function name")
    ap.add_argument("--input",    default="3765_full.csv")
    ap.add_argument("--out",      default="data/lambda_results.jsonl")
    ap.add_argument("--resume",   action="store_true")
    ap.add_argument("--region",   default="us-east-1")
    ap.add_argument("--limit",    type=int, default=0)
    args = ap.parse_args()

    domains = load_domains(Path(args.input))
    if args.limit:
        domains = domains[:args.limit]
    print(f"[*] {len(domains)} domains loaded")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done_set = load_done(out_path) if args.resume else set()

    remaining = [d for d in domains if d not in done_set]
    print(f"[*] {len(remaining)} to scan ({len(done_set)} already done)")

    batches = [remaining[i:i+BATCH_SIZE] for i in range(0, len(remaining), BATCH_SIZE)]
    print(f"[*] {len(batches)} Lambda batches of {BATCH_SIZE}, {MAX_PARALLEL} parallel")

    from botocore.config import Config
    client = boto3.client("lambda", region_name=args.region,
                          config=Config(read_timeout=310, connect_timeout=15,
                                        retries={"max_attempts": 2}))
    t0     = time.time()
    done   = 0
    errors = 0

    with open(out_path, "a", encoding="utf-8") as fout:
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
            futures = {
                pool.submit(invoke_batch, client, args.function, batch, i): i
                for i, batch in enumerate(batches)
            }
            for fut in as_completed(futures):
                batch_id = futures[fut]
                try:
                    results = fut.result()
                    for r in results:
                        fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                    done += len(results)
                except Exception as e:
                    print(f"  [!] batch {batch_id} exception: {e}")
                    errors += 1

                if (batch_id + 1) % 20 == 0:
                    fout.flush()
                    elapsed = time.time() - t0
                    rate    = done / elapsed if elapsed else 1
                    remain  = (len(remaining) - done) / rate if rate else 0
                    print(f"  [batch {batch_id+1}/{len(batches)}] {done} done, "
                          f"{errors} errors, ETA {remain/60:.0f} min")

    elapsed = time.time() - t0
    print(f"\n[+] Done: {done} domains, {errors} batch errors. Time: {elapsed/60:.1f} min")
    print(f"    Output: {out_path}  ({out_path.stat().st_size//1024} KB)")


if __name__ == "__main__":
    main()
