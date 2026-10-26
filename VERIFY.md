# Verification Guide

This document distinguishes the signed historical evidence snapshot from the evolving repository.

**The existing signed manifest belongs to the preserved snapshot at [commit `5367ea8`](https://github.com/phishdestroy/nicenic-evidence/tree/5367ea8b6d188e99b46bf83313ffa14ab904ed94).** README statistics, documentation, and generated feeds on `main` have changed since that snapshot. Verify the signed files from that revision, using its manifest, signature, and `allowed_signers` together. The historical manifest and signature are retained unchanged.

[Download the pinned snapshot](https://github.com/phishdestroy/nicenic-evidence/archive/5367ea8b6d188e99b46bf83313ffa14ab904ed94.zip), extract it into a separate directory, and run the commands below there. The signature authenticates the manifest; checking the file hashes is a separate step.

## 1 · SHA-256 Checksums

From the pinned snapshot directory, verify the files against its manifest:

```bash
# Linux / macOS
sha256sum -c SHA256SUMS.txt

# Windows (PowerShell)
Get-Content SHA256SUMS.txt | Where-Object { $_ -notmatch '^#' -and $_ -ne '' } | ForEach-Object {
    $hash, $file = $_ -split '  ', 2
    $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $hash) { "OK $file" } else { "FAIL $file" }
}
```

An `OK` means the file matches the manifest. A `FAIL` means its bytes differ; a missing file is also a verification failure. First confirm that files and manifest come from the same revision. A mismatch on the moving `main` branch can result from a documented update and does not, by itself, prove tampering.

## 2 · SSH Signature Verification

The `SHA256SUMS.txt` manifest is signed with an Ed25519 key. Verify the signature:

```bash
ssh-keygen -Y verify \
    -f allowed_signers \
    -I phishdestroy@phishdestroy.io \
    -n evidence \
    -s SHA256SUMS.txt.sig \
    < SHA256SUMS.txt
```

Expected output:
```
Good "evidence" signature for phishdestroy@phishdestroy.io with ED25519 key SHA256:q6ct6b3gNhZicoXUUXiaBSM5xmcR4GFi7vey8yhGQZQ
```

The signing key fingerprint is `SHA256:q6ct6b3gNhZicoXUUXiaBSM5xmcR4GFi7vey8yhGQZQ` (ED25519).  
The public key is in `allowed_signers` — do not modify this file before verifying.

## 3 · Regenerate data.json

Rebuild only in a separate working copy of the same snapshot, after verifying the original files:

```bash
python docs/build_datajson.py
# Then compare docs/data.json hash against SHA256SUMS.txt
```

## 4 · IOC Feed Counts

Counts change as the published feeds are updated. Count the files from the revision you are auditing; compare them with the README and feed metadata from that same revision. Historical live-content classifications and the broader production blocklists are different datasets.

```python
import csv
from pathlib import Path

for name in ("ioc/domains_high.txt", "ioc/domains_all_malicious.txt"):
    with Path(name).open(encoding="utf-8") as source:
        count = sum(1 for line in source if line.strip() and not line.lstrip().startswith("#"))
    print(f"{name}: {count:,} domain entries")

for name in ("ioc/indicators.csv", "data/enriched.csv"):
    with Path(name).open(encoding="utf-8-sig", newline="") as source:
        rows = csv.reader(source)
        next(rows, None)  # header
        count = sum(1 for row in rows if row)
    print(f"{name}: {count:,} data rows")
```

## 5 · Chain of Custody

Full procedural documentation is in [`PROVENANCE.md`](PROVENANCE.md).

TLP:CLEAR — this evidence package may be shared freely with ICANN, law enforcement,
threat intelligence platforms, and academic researchers.
