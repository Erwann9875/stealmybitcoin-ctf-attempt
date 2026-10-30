# Steal My Bitcoin CTF exploit

Target-locked proof for the intentionally vulnerable challenge at
[`old.stealmybitcoin.com`](https://old.stealmybitcoin.com/).

The runner connects directly to the challenge over TLS and executes only
`print-flag` inside the PHP container. It cannot be pointed at another host.

Read the current [challenge terms](https://old.stealmybitcoin.com/terms.html)
before use. This chain intentionally reaches PHP's controlled out-of-memory
path, while the published terms prohibit resource exhaustion. Obtain organizer
confirmation that this exact request pattern remains permitted before running
it.

## Run

Requires Python 3.10 or newer and no third-party packages.

```bash
python3 remote_proof.py
```

The runner performs one attempt and never retries automatically.

```bash
python3 remote_proof.py --timeout 20
```

On success, the runner prints the challenge marker followed by:

```text
RESULT=CTF_PRINT_FLAG_CONFIRMED
```

## Fixed scope

- Host: `https://old.stealmybitcoin.com`
- Paths: `/ping.php` and `/php-version.php`
- Build: challenge PHP 8.4.26 Alpine profile
- Command: `print-flag`
- Transport: direct TLS with one persistent connection

There are no options for another target, command, PHP profile, endpoint, proxy,
or heap calibration. Each response is checked before the next request is sent,
and availability errors stop the runner immediately.

This code is not a general PHP vulnerability scanner or cross-version exploit.
Use it only against the challenge while its authorization terms remain active.
