# enum4linux
A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts.

Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com.

It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.

The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.

Also see: https://labs.portcullis.co.uk/tools/enum4linux/

## Batch and multi-subnet enumeration

Targets can be hostnames, IPv4 addresses, IPv4 CIDR ranges, or lists. The
batch runner limits concurrent hosts, rate-limits host starts, retries only
transient host failures, and deduplicates targets and result records.

```sh
perl enum4linux.pl -U -S --targets '10.0.0.0/24,10.0.1.0/24'
perl enum4linux.pl -U -G --target-file targets.txt --threads 24 --rate 6
```

Batch controls:

```text
-t, --threads N        Concurrent host workers (default: 32)
-q, --rate N           Host attempts started per second (default: 8)
-T, --retries N        Retries after transient failure (default: 2)
    --retry-delay SEC  Exponential retry backoff base (default: 1)
    --host-timeout SEC Hard timeout for one host attempt (default: 30)
    --time-budget SEC  Whole-batch deadline (default: 600; 0 disables)
    --targets LIST     Comma/space-separated hosts or IPv4 CIDRs
    --target-file FILE Read targets from a file; # starts a comment
```

Authentication failures and account-lockout responses are treated as
permanent and are never retried. A host is never scanned by more than one
worker at a time. Accept/routing-only addresses in IPv4 CIDRs (`/30` or
larger) are skipped automatically.

With the defaults, 500 hosts have at most 62.5 seconds of start-rate delay
and 16 concurrency waves of at most 30 seconds each, staying below the
600-second budget when attempts finish within their per-host timeout.

## Tests

The mock SMB suite does not require Samba:

```sh
prove -v t/mock_smb.t
```
