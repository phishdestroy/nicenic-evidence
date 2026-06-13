# Verification Guide

This document describes how to independently verify the integrity of the published evidence files.

## 1 · SHA-256 Checksums

Verify all data files against the published manifest:

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

Expected: all files print `OK`. Any `FAIL` indicates tampering or file corruption.

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

Confirm the published report data matches the canonical enriched dataset:

```bash
python docs/build_datajson.py
# Then compare docs/data.json hash against SHA256SUMS.txt
```

## 4 · IOC Feed Counts

| File | Expected rows |
|---|---|
| `ioc/domains_high.txt` | 18,305 domains |
| `ioc/domains_all_malicious.txt` | 18,927 domains |
| `ioc/indicators.csv` | 18,927 indicators |
| `data/enriched.csv` | 86,114 rows (+ header) |

```bash
# Quick row-count verification
grep -c "^[^#]" ioc/domains_high.txt
grep -c "^[^#]" ioc/domains_all_malicious.txt
wc -l data/enriched.csv
```

## 5 · Chain of Custody

Full procedural documentation is in [`PROVENANCE.md`](PROVENANCE.md).

TLP:CLEAR — this evidence package may be shared freely with ICANN, law enforcement,
threat intelligence platforms, and academic researchers.
