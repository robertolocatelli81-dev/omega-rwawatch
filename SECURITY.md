# Security policy

## Reporting a vulnerability

Report a suspected vulnerability in this repository **privately** to the author,
roberto.locatelli.81@gmail.com, with the commit hash and a reproducer. Please do not open a public
issue for anything exploitable. If the repository is on GitHub, its "Report a vulnerability"
(Security tab → Advisories) is the equivalent private channel.

- You will receive an acknowledgement as soon as reasonably possible — best effort: this is an
  independently maintained project by one person, not a staffed security team; no SLA is promised.
- Coordinated disclosure is preferred: please allow a reasonable window for a fix before publishing
  details.
- Verified fixes are tagged and credited to the reporter (unless anonymity is requested).

## Supported versions

Only the **latest tagged release** (or, before the first tag, the head of `main`) receives security
fixes.

## Scope

In scope: the code in this repository — the reader (`rwawatch.py`), the council
(`rwawatch_agents.py`), the orchestrator (`rwawatch_orchestrator.py`) and the tests — including any
way to make a chain that failed its node-identity, freshness or positive-control gate be reported as
assessed, any way to make the hash-chained memory verify `PASS` after an alteration, and any way to
make the council vote `QUIET` on a reading it should flag.

Out of scope: the public RPC nodes (publicnode.com, the Solana and Aptos public endpoints, Stellar
Horizon), the explorer search APIs (Blockscout, BscScan), the issuers' address pages and the optional
`omega-evidence` package — third-party services and code this project only reads from or calls.
Report issues in those to their operators or maintainers.

## Data

The watcher reads **public** on-chain state only (token names, symbols, decimals, total supplies,
contract code, owner addresses, explorer search results) and records hashes and readings. No personal
data is collected or processed. The optional signing seed and ML-DSA key live outside the repository
(`~/.config/omega-rwawatch/`, mode 0600) and are never written into it; the production memory, the
latest record and the evidence packs are gitignored.

## Honest scope

This project verifies and records public on-chain facts at a recorded block and the integrity of its
own memory. It does not value, rate or forecast any fund, is not an official NAV, price or
assets-under-management feed, does not tell an imitation from a wrapper, and is not financial,
investment or legal advice. Nothing here is a regulatory conformity claim.
