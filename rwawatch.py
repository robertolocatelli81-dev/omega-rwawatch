#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMEGA-RWAWatch · core — real on-chain snapshot of tokenized real-world-asset funds + vendored hash-chain.

Watches the tokens of five tokenized money-market / treasury funds — BlackRock BUIDL (+ BUIDL-I, tokenized by
Securitize), J.P. Morgan JLTXX and MONY, Franklin Templeton BENJI, Circle USYC — on the public chains where they are
deployed (7 EVM chains, Solana, Aptos, Stellar). For each chain it reads, from a public node and at a recorded block /
slot / ledger version, the token's name, symbol, decimals and total supply, the controlling key, and the STRUCTURE of
the contract (proxy size, implementation address and a SHA-256 of the implementation's code — or the Diamond's loupe
for EIP-2535 — presence of EIP-712 / EIP-2612 / EIP-3009 entry points). Before trusting a chain's readings it checks
the node's identity and freshness and runs a POSITIVE CONTROL on the same node: a token known to expose EIP-712 (USDC,
or a PancakeSwap LP on BNB), or the non-EVM equivalent, must be seen as expected; if not, that chain is reported as
NOT ASSESSED, never as clean.

Independent project, not affiliated with, reviewed or endorsed by BlackRock, Securitize, J.P. Morgan, Franklin
Templeton or Circle; not an official NAV/price/AUM feed; not financial advice.

Honest scope: this VERIFIES and RECORDS public on-chain facts at a block and tracks them over time (the hash-chained
memory IS the record). It does NOT predict, it does not value any fund, and a total supply is not assets under
management. Every address comes from the issuer's own page (provenance recorded per entry in REGISTRY /
NONEVM_REGISTRY); the one exception is BUIDL on BNB Chain, which is not on BlackRock's page and is tied to the listed
contracts by a shared owner(). Stdlib only; the hash-chain is VENDORED (never imports from ~/omega/).

Run:  python3 rwawatch.py            # one snapshot, printed, not saved
"""
import hashlib
import json
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

LEDGER = "rwawatch_ledger.jsonl"
GENESIS = "0" * 64
_CTX = ssl.create_default_context()
USER_AGENT = "omega-rwawatch/0.1"

# Public RPC endpoints (one per chain; a failure is reported, never papered over).
RPC = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
}

# The chain each URL must answer for (eth_chainId). A load balancer that routes to another network would otherwise
# pass the positive control — USDC exists on every chain — and record another chain's state under this name.
CHAIN_IDS = {"ethereum": 1, "arbitrum": 42161, "optimism": 10, "polygon": 137, "avalanche": 43114, "bsc": 56,
             "base": 8453}
MAX_BLOCK_AGE_S = 900        # a node whose latest block is older than this is lagging: the chain is NOT ASSESSED

# Where same-named tokens are searched for (explorer search APIs; a chain without one is reported "not searched").
DISCOVERY = {
    "ethereum": ("blockscout", "https://eth.blockscout.com"),
    "arbitrum": ("blockscout", "https://arbitrum.blockscout.com"),
    "optimism": ("blockscout", "https://optimism.blockscout.com"),
    "polygon": ("blockscout", "https://polygon.blockscout.com"),
    "bsc": ("bscscan-search", "https://bscscan.com/searchHandler"),
}
DISCOVERY_TERMS = ("BUIDL", "BlackRock USD Institutional")      # BUIDL's (kept: the first searched)
# Per fund: the search terms and the issuer-name needle a same-named token is matched against (measured on Blockscout
# 25/09/2026: the bare term "BENJI" returns a full page of unrelated memecoins, so BENJI is searched by the fund name;
# "JPMorgan" alone returns tokenized JPMorgan Chase STOCKS, so JLTXX is searched by its ticker and fund name).
FUND_SEARCH = {
    "BUIDL": {"terms": DISCOVERY_TERMS, "needle": ("blackrock",)},
    "JLTXX": {"terms": ("JLTXX", "JPMorgan OnChain"), "needle": ("jpmorgan", "j.p. morgan")},
    # "Franklin Templeton BENJI" is how explorers index the OFFICIAL contracts (the search control needs it);
    # "Franklin OnChain" finds same-named tokens that carry the fund's legal name
    "BENJI": {"terms": ("Franklin Templeton BENJI", "Franklin OnChain"), "needle": ("franklin",)},
    "USYC": {"terms": ("USYC",), "needle": ("usyc",)},
}
# The two contract shapes the registered BUIDL deployments have (measured 25/09/2026)
SECURITIZE_SHAPES = ({"proxy_code_bytes": 703, "implementation_slot": "slot1"},
                     {"proxy_code_bytes": 170, "implementation_slot": "eip1967"})

# Official source of the addresses (checked 25/09/2026, page sha256 a0c2c276…): it lists 6 of the 7 EVM addresses below,
# and the Solana and Aptos ones; not BNB Chain.
OFFICIAL_PAGE = "https://www.blackrock.com/corporate/compliance/scams-and-fraud/blackrock-token-addresses"
OFFICIAL = f"listed on {OFFICIAL_PAGE}"
# owner() of all seven registered contracts on 25/09/2026, BNB included: one externally owned account (no code), i.e.
# the same private key on every chain. A change is flagged; a same-named token with another owner is not a deployment
# of this issuer's key.
EXPECTED_OWNER = "0xe01605f6b6dc593b7d2917f4a0940db2a625b09e"

# Other issuers' official address lists (checked 25/09/2026; sha256 of the raw HTML as fetched)
BENJI_PAGE = "https://digitalassets.franklintempleton.com/benji/benji-contracts/"
BENJI_OFFICIAL = f"listed on {BENJI_PAGE} (Benji DevHub, raw HTML sha256 58176ad2…)"
USYC_PAGE = "https://developers.circle.com/tokenized/usyc/smart-contracts"
USYC_OFFICIAL = f"listed on {USYC_PAGE} (Circle docs, raw HTML sha256 a6105f97…)"

# The addresses watched, each with where it was found (25/09/2026). Structure fingerprints are READ each run, not
# asserted here, so a change of implementation shows up as a change in the record.
REGISTRY = [
    {"chain": "ethereum", "token": "BUIDL", "address": "0x7712c34205737192402172409a8f7ccef8aa2aec",
     "provenance": f"{OFFICIAL} (also Etherscan label 'BlackRock: BUIDL Token')"},
    {"chain": "ethereum", "token": "BUIDL-I", "address": "0x6a9da2d710bb9b700acde7cb81f10f1ff8c89041",
     "provenance": f"{OFFICIAL}"},
    {"chain": "arbitrum", "token": "BUIDL", "address": "0xA6525Ae43eDCd03dC08E775774dCAbd3bb925872",
     "provenance": f"{OFFICIAL}"},
    {"chain": "optimism", "token": "BUIDL", "address": "0xa1cdab15bba75a80df4089cafba013e376957cf5",
     "provenance": f"{OFFICIAL}"},
    {"chain": "polygon", "token": "BUIDL", "address": "0x2893Ef551B6dD69F661Ac00F11D93E5Dc5Dc0e99",
     "provenance": f"{OFFICIAL}"},
    {"chain": "avalanche", "token": "BUIDL", "address": "0x53FC82f14F009009b440a706e31c9021E1196A2F",
     "provenance": f"{OFFICIAL}"},
    {"chain": "ethereum", "token": "JLTXX", "address": "0x09864f52B035AE22eE739dFa5c748fA080D07bD8",
     "provenance": "J.P. Morgan Asset Management press release 13/05/2026 (am.jpmorgan.com, raw HTML sha256 c3f91b60…, the only address in it)",
     "expected_owner": "0x5ae5d4ada523985dbab22cf046599979897c8418"},
    # MONY: FOUND by this watcher's search (owned by the key recorded for JLTXX), then confirmed on the issuer's
    # release — the only address in it. Same Diamond shape as JLTXX (16 facets, 68 selectors, 25/09/2026).
    {"chain": "ethereum", "token": "MONY", "address": "0x6a7c6aa2b8b8a6A891dE552bDEFFa87c3F53bD46",
     "provenance": "J.P. Morgan Asset Management press release 15/12/2025 (am.jpmorgan.com, raw HTML sha256 3dc77e38…, "
                   "the only address in it); found first by owner() in this watcher's search, 25/09/2026",
     "expected_owner": "0x5ae5d4ada523985dbab22cf046599979897c8418"},
    {"chain": "bsc", "token": "BUIDL", "address": "0x2D5BdC96D9C8AabBDB38c9A27398513e7E5ef84F",
     "provenance": "NOT on the official page (25/09/2026); BscScan search (is_checked, website securitize.io/blackrock/BUIDL) "
                   "and owner() equal to the owner of the six officially listed contracts"},
] + [
    # Franklin Templeton BENJI (FOBXX): no owner() on these contracts and an empty EIP-1967 admin slot (25/09/2026) —
    # control sits in Franklin's own modules, not watched here; expected_owner None = no owner check, said, not faked
    {"chain": ch, "token": "BENJI", "address": a, "provenance": BENJI_OFFICIAL, "expected_owner": None}
    for ch, a in (("ethereum", "0x3DDc84940Ab509C11B20B76B466933f40b750dc9"),
                  ("polygon", "0x408A634B8a8f0dE729B48574a3a7Ec3fE820B00A"),
                  ("arbitrum", "0xB9e4765BCE2609bC1949592059B17Ea72fEe6C6A"),
                  ("avalanche", "0xE08b4c1005603427420e64252a8b120cacE4D122"),
                  ("base", "0x60CfC2b186a4CF647486e42c42B11cC6D571d1E4"))
] + [
    # Circle USYC: owner() an externally owned account on each chain (measured 25/09/2026)
    {"chain": "ethereum", "token": "USYC", "address": "0x136471a34f6ef19fE571EFFC1CA711fdb8E49f2b",
     "provenance": USYC_OFFICIAL, "expected_owner": "0x13ff8cabb86edf94a2df4f98773bda4005182dd6"},
    {"chain": "bsc", "token": "USYC", "address": "0x8D0fA28f221eB5735BC71d3a0Da67EE5bC821311",
     "provenance": USYC_OFFICIAL, "expected_owner": "0xcd636d955a95385ec5e2776b167b92e89ef6f70e"},
]

# Positive controls: tokens that DO expose EIP-712 on each chain. If the reader cannot see it there, it cannot be
# trusted to report its absence on BUIDL.
CONTROLS = {
    "ethereum": ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    "arbitrum": ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    "optimism": ("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
    "polygon": ("USDC", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
    "avalanche": ("USDC", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"),
    "bsc": ("Cake-LP", "0x0eD7e52944161450477ee417DE9Cd3a859b14fD0"),
    "base": ("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
}

# ───────────────────────── non-EVM chains (same method: network identity, freshness, positive control, readings) ──
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
SOLANA_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"          # mainnet-beta
APTOS_API = "https://api.mainnet.aptoslabs.com/v1"
APTOS_CHAIN_ID = 1                                                        # mainnet
NONEVM_REGISTRY = [
    {"chain": "solana", "token": "BUIDL", "address": "GyWgeqpy5GueU2YbkE8xqUeVEokCMMCEeUrfbtMw6phr",
     "provenance": f"{OFFICIAL}", "expected_owner": "APm3MWbXfMMKAWgsDVnxcAGbLjvRxubPu1A8a5SA2kbJ"},
    {"chain": "aptos", "token": "BUIDL", "address": "0x50038be55be5b964cfa32cf128b5cf05f123959f286b4cc02b86cafd48945f89",
     "provenance": f"{OFFICIAL}", "expected_owner": "0x4de5876d8a8e2be7af6af9f3ca94d9e4fafb24b5f4a5848078d8eb08f08e808a"},
    # BENJI on Solana: the mint is its own mint authority (a program-derived setup, measured 25/09/2026)
    {"chain": "solana", "token": "BENJI", "address": "5Tu84fKBpe9vfXeotjvfvWdWbAjy3hqsExvuHgFqFxA1",
     "provenance": BENJI_OFFICIAL, "expected_owner": "5Tu84fKBpe9vfXeotjvfvWdWbAjy3hqsExvuHgFqFxA1"},
    {"chain": "solana", "token": "USYC", "address": "7LWanZteUKtvFjv4MHYgKXXdAuCQYFPJysL9pxxdRQGn",
     "provenance": USYC_OFFICIAL, "expected_owner": "DZ7j2YLDq7847t2HtCWaDQUTpLJ4BinPGsY8w9Aai63y"},
    # BENJI on Aptos: the object owner is the address the official page lists as "Authorization Module"
    {"chain": "aptos", "token": "BENJI", "address": "0x7b5e9cac3433e9202f28527f707c89e1e47b19de2c33e4db9521a63ad219b739",
     "provenance": BENJI_OFFICIAL, "expected_owner": "0x4705f33d665762a5371d3b8786e63749814e749295ea73269b379c84b756d83a"},
    # BENJI on Stellar: a classic issued asset; its "owner" is the issuer account's signer set + thresholds, recorded as
    # a SHA-256 fingerprint (25/09/2026: master key weight 0, 14 signers, thresholds 2/2/6)
    {"chain": "stellar", "token": "BENJI", "address": "GBHNGLLIE3KWGKCHIKMHJ5HVZHYIK7WTBE4QF5PLAKL4CJGSEU7HZIW5",
     "provenance": BENJI_OFFICIAL,
     "expected_owner": "signers-sha256:04d548a15365ed81974e173dfb4d40e75a520b874f680655e7b296f312431bd5"},
]
STELLAR_HORIZON = "https://horizon.stellar.org"
STELLAR_PASSPHRASE = "Public Global Stellar Network ; September 2015"
STELLAR_CONTROL = ("USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
# Solana control: a Token-2022 mint KNOWN to carry the extensions watched on BUIDL (PYUSD); Aptos control: a fungible
# asset known to be readable (USDC) and a framework module known to use ed25519 (0x1::account) for the bytecode scan.
SOLANA_CONTROL = ("PYUSD", "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", ("permanentDelegate", "transferHook"))
APTOS_CONTROL = ("USDC", "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b")
SIG_NEEDLES = ("ed25519", "secp256k1", "multi_ed25519", "bls12381")


# ───────────────────────── tokenized ETF / equity-tracker layer (added 2026-09-28) ──
# A DISTINCT asset class from the money-market / treasury FUNDS above: these tokens track a LISTED ETF, as their issuer describes them.
# Same method — every address is READ on-chain at a block, the control key (owner() on EVM, mint/freeze authority on
# Solana) is compared to the one recorded for the issuer, and the token's control SURFACE is fingerprinted. `status`
# is the ISSUER's DECLARED state (listed vs redemption_only), marked declared-with-date, NEVER measured on-chain.
# Honest scope: total supply is a token count, NOT AUM and NOT the ETF's NAV; this VERIFIES on-chain facts, it does
# not value anything. Of the seven contracts registered on 2026-09-28, three are redemption-only per their issuer. The
# OpenSea-listed same-named "QQQX" AAmD… (legacy Token program, no authorities) is not tied to the xStocks keys and is
# NOT registered (checked by hand 2026-09-28; this layer runs no search).
#
# ERC-3643 (T-REX) and ERC-7943 (uRWA, Final since 2026-05-05, fungible variant) permissioned-token entry points: the
# 4-byte selector is the keccak-256 of the function signature (computed offline 2026-09-28 with a positive control,
# transfer(address,uint256) = a9059cbb; recomputable — so hardcoding them keeps the runtime stdlib-only). Sources:
# eips.ethereum.org/EIPS/eip-3643 and the Final text of ERCS/erc-7943.md (ethereum/ERCs). canTransfer(address,address,uint256)
# has the same selector in both — on the token in uRWA, on the Compliance module in T-REX; forcedTransfer is on the
# token in both. The pre-Final draft names (isTransferAllowed, isUserAllowed,
# forceTransfer) were renamed before Final and are NOT searched. Presence on the executing code is
# a forward-looking signal (issuers adopting on-chain compliance). ABSENCE is asserted only where the scan's positive
# control passes (the token exposes `permit`, as the three Backed bTokens do); elsewhere (IBITon) it is not assessed.
PERMISSIONED_SELECTORS = {
    "erc3643+7943:canTransfer": "e46638e6", "erc3643+7943:forcedTransfer": "9fc1d0e7",
    "erc3643:compliance": "6290865d", "erc3643:identityRegistry": "134e18f4", "erc3643:isFrozen": "e5839836",
    "erc3643:setAddressFrozen": "c69c09cf",
    "erc7943:canSend": "2bc06a92", "erc7943:canReceive": "90d370ba", "erc7943:getFrozenTokens": "158b1a57",
    "erc7943:setFrozenTokens": "ebe45cba",
}
# Positive control of the byte scan itself: EIP-2612 `permit` (d505accf, already in SELECTORS) is exposed by bCSPX. If
# the scanner cannot see permit where it exists, it cannot be trusted to report the ABSENCE of the 3643/7943 selectors.
PERMISSIONED_SCAN_CONTROL_SELECTOR = "d505accf"

# Backed key that owns the bToken (ETF) contracts, per chain, measured 2026-09-28 (Base has its own key).
BACKED_OWNER_ETH = "0x22f2dfe84a2eacfe5d3ca81d26e610cb94eb1603"
BACKED_OWNER_BASE = "0xd1966bd72695789ec9c245f0bf5a8512b56c1d80"
# xStocks (Backed's brand for these Token-2022 mints) Solana control authorities, shared across its Token-2022 mints, measured 2026-09-28.
XSTOCKS_MINTER = "7pt9tkctJPK7PPNQJ77GKg8ZffSF6QxoMiCFYHxrtaCj"
XSTOCKS_FREEZER = "JDq14BWvqCRFNu1krb12bcRpbGtJZ1FLEakMw6FdxJNs"
XSTOCKS_TOKEN2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# Ondo Global Markets — IBITon, a tokenized tracker of BlackRock's iShares Bitcoin Trust ETF (IBIT). PRIMARY SOURCE:
# the issuer's own asset page, whose embedded data lists `supportedNetworks` for IBIT — exactly Ethereum (chainId 1),
# BSC (56) and Solana (101) with the three addresses registered below (read 2026-09-28; the page is dynamic — each fetch
# has a different sha256, ~386,753 bytes — so what is reproducible is the supportedNetworks list, not a page hash). The page names the issuer "Ondo Global Markets (BVI) Limited". `status` "listed" is DECLARED: the
# page lists the token on the three networks and each has a non-zero supply on-chain (measured, not a lifecycle);
# launch dates are the issuer's / press announcements, not measured here.
ONDO_PAGE = "https://app.ondo.finance/assets/ibiton"
ONDO_OFFICIAL = f"listed on {ONDO_PAGE} (issuer's asset page, embedded supportedNetworks list, read 2026-09-28; dynamic page, no stable hash)"
ONDO_ISSUER = "Ondo Global Markets (BVI) Limited"
IBITON_UNDERLYING = "iShares Bitcoin Trust ETF (IBIT)"
IBITON_STATUS_SOURCE = ("listed: the issuer's asset page lists IBITon on Ethereum, BNB Chain and Solana (read 2026-09-28); "
                        "Ondo Stocks launched on Ethereum 2025-09-03 (The Block) and on Solana 2026-01-21 (ondo.finance/blog)")
# Sole DEFAULT_ADMIN_ROLE member of the IBITon beacon proxies, per chain (a contract with code; also the beacon's owner()).
IBITON_ADMIN_ETH = "0x3715b2154d2ff4c5b027c7a1f734b53f27bc34f1"
IBITON_ADMIN_BSC = "0x8860bbfc7a83e4788a981f4e9f30878331413b26"
# IBITon Solana mint authority (also the authority of every control extension) and freeze authority, measured 2026-09-28.
IBITON_SOL_MINTER = "9foMHsSDq7nMg4WPusSz9eY7tyxyukqborA8GyU5cUxD"
IBITON_SOL_FREEZER = "51QVCuHfL1FeNjd8BDeffCKhCcAYoULnVB3yjNhShiuK"

# EVM ETF tokens. Provenance is recorded per entry: the Backed bToken addresses come from the issuer's product pages
# (explorer links under 'Smart Contracts'), also carried by explorer labels; the two on Ethereum share one owner(), the
# Base one has another key. Each is verified at the block recorded in the run. Backed's product pages say bTokens are no longer available for new issuance (redemption supported).
ETF_REGISTRY_EVM = [
    {"chain": "ethereum", "token": "bCSPX", "address": "0x1e2c4fb7ede391d116e6b41cd0608260e8801d59",
     "underlying": "iShares Core S&P 500 UCITS ETF (CSPX, IE00B5BMR087)", "issuer": "Backed Assets (JE) Limited",
     "expected_owner": BACKED_OWNER_ETH, "status": "redemption_only",
     "status_source": "issuer product page (read 2026-09-28): 'no longer available for new issuance', redemption supported; no date given there",
     "provenance": "issuer product page assets.backed.fi/products/bcspx (explorer links under 'Smart Contracts', raw HTML "
                   "read 2026-09-28); also the Etherscan label 'Backed Finance: bCSPX Token'; on-chain name/symbol/owner verified "
                   "2026-09-28, owner() = the key that also owns bIB01"},
    {"chain": "base", "token": "bCSPX", "address": "0xc3ce78b037dda1b966d31ec7979d3f3a38571a8e",
     "underlying": "iShares Core S&P 500 UCITS ETF (CSPX, IE00B5BMR087)", "issuer": "Backed Assets (JE) Limited",
     "expected_owner": BACKED_OWNER_BASE, "status": "redemption_only",
     "status_source": "issuer product page (read 2026-09-28): 'no longer available for new issuance', redemption supported; no date given there",
     "provenance": "issuer product page assets.backed.fi/products/bcspx (Base explorer link, raw HTML read 2026-09-28); "
                   "also BaseScan; on-chain name/symbol/owner verified 2026-09-28 (Base owner differs from Ethereum)"},
    {"chain": "ethereum", "token": "bIB01", "address": "0xca30c93b02514f86d5c86a6e375e3a330b435fb5",
     "underlying": "iShares $ Treasury Bond 0-1yr UCITS ETF", "issuer": "Backed Assets (JE) Limited",
     "expected_owner": BACKED_OWNER_ETH, "status": "redemption_only",
     "status_source": "issuer product page (read 2026-09-28): 'no longer available for new issuance', redemption supported; no date given there",
     "provenance": "issuer product page assets.backed.fi/products/bib01 (explorer links, raw HTML read 2026-09-28); also "
                   "the Etherscan label 'Backed Finance: bIB01 Token'; on-chain name/symbol/owner verified 2026-09-28, owner() = the key that also owns bCSPX"},
] + [
    # IBITon (Ondo Global Markets): EIP-1967 BEACON proxies of 824 bytes; owner() REVERTS. Control key MEASURED
    # 28/09/2026: AccessControl DEFAULT_ADMIN_ROLE has exactly ONE member (getRoleMemberCount = 1, hasRole confirmed),
    # a contract on each chain that is also the beacon's owner(). compliance() is present and answers with a contract
    # address (1,403 bytes; its owner() is a key other than IBITon's admin — the relation to the issuer is not
    # established on-chain). identityRegistry(), isFrozen() and canTransfer() revert when called (measured 28/09/2026).
    {"chain": ch, "token": "IBITon", "address": a, "underlying": IBITON_UNDERLYING, "issuer": ONDO_ISSUER,
     "expected_owner": adm, "expected_owner_kind": "AccessControl DEFAULT_ADMIN_ROLE (sole member, measured 2026-09-28)",
     "status": "listed", "status_source": IBITON_STATUS_SOURCE,
     "provenance": f"{ONDO_OFFICIAL}; on-chain name/symbol/beacon/admin role verified 2026-09-28"}
    for ch, a, adm in (("ethereum", "0x122940c4c5f9ccfae7fa86455a42d3ec140855ce", IBITON_ADMIN_ETH),
                       ("bsc", "0x68b07cef227cea1b2b6683921c8c825cd5c69ec7", IBITON_ADMIN_BSC))
]
# Solana ETF tokens (xStocks and Ondo, Token-2022). Control key = mint authority; the permissioned surface is the set of
# Token-2022 extensions (permanentDelegate / defaultAccountState / pausable / transferHook / confidentialTransfer).
ETF_REGISTRY_SOLANA = [
    {"chain": "solana", "token": "SPYx", "address": "XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W",
     "underlying": "SPDR S&P 500 ETF Trust (SPY)", "issuer": "Backed Assets (JE) Limited (xStocks brand)",
     "expected_mint_authority": XSTOCKS_MINTER, "expected_freeze_authority": XSTOCKS_FREEZER,
     "status": "listed", "status_source": "listed in the xStocks product catalog (read 2026-09-28); lifecycle not stated there, not measured on-chain",
     "provenance": "issuer catalog xstocks.com/products (embedded JSON, symbol SPYx -> solana mint, raw HTML read 2026-09-28); "
                   "underlying per assets.backed.fi/products/sp500-xstock ('SPYx tracks the price of SPDR S&P 500 ETF Trust'); "
                   "also Solana Compass. Tied on-chain: "
                   "Token-2022, mint/freeze authority identical to xStocks NVDAx (Xsc9qv…), verified 2026-09-28"},
    # IBITon on Solana: Token-2022 mint (vanity '…Kondo') listed by the issuer's page; mint / freeze authority and the
    # control extensions (confidentialTransferMint, defaultAccountState, pausableConfig, transferHook with no hook
    # program set) measured 28/09/2026
    {"chain": "solana", "token": "IBITon", "address": "6JLG8iUkAuqiBhL3j2ckDMDf5oWAa6awmyaWezKondo",
     "underlying": IBITON_UNDERLYING, "issuer": ONDO_ISSUER,
     "expected_mint_authority": IBITON_SOL_MINTER, "expected_freeze_authority": IBITON_SOL_FREEZER,
     "status": "listed", "status_source": IBITON_STATUS_SOURCE,
     "provenance": f"{ONDO_OFFICIAL}; Token-2022 mint, metadata name/symbol and authorities verified 2026-09-28"},
]
# The Token-2022 extensions that constitute issuer CONTROL over holders (as opposed to plain metadata).
SOLANA_CONTROL_EXTENSIONS = ("permanentDelegate", "defaultAccountState", "pausableConfig", "transferHook",
                             "confidentialTransferMint")


def _post_json(url, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(NETWORK_RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
                out = json.loads(r.read())
            break
        except (OSError, ssl.SSLError):
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
    return out.get("result")


def _get_json(url, timeout=25):
    for attempt in range(NETWORK_RETRIES + 1):
        try:
            return _http_json(url, timeout)
        except (OSError, ssl.SSLError):
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)


def _sol_mint(address):
    v = _post_json(SOLANA_RPC, "getAccountInfo", [address, {"encoding": "jsonParsed", "commitment": "finalized"}])
    val = v["value"]
    info = val["data"]["parsed"]["info"]
    ext = {e["extension"]: e.get("state") for e in info.get("extensions", [])}
    return v["context"]["slot"], val["owner"], info, ext


def solana_node_gate(now=None):
    """Genesis hash (mainnet-beta), freshness of the finalized slot and the PYUSD Token-2022 positive control — the
    gate SHARED by the fund layer (read_solana) and the ETF layer (fetch_etf_signal), written and tested once.
    Returns {"ok": True, "node", "slot", "ctl"} when the chain may be read, else a NOT-ASSESSED dict."""
    genesis = _post_json(SOLANA_RPC, "getGenesisHash", [])
    slot = _post_json(SOLANA_RPC, "getSlot", [{"commitment": "finalized"}])
    bt = _post_json(SOLANA_RPC, "getBlockTime", [slot])
    node = {"chain_id": genesis, "expected_chain_id": SOLANA_GENESIS, "block": slot, "block_timestamp": bt,
            "block_age_s": int((now if now is not None else time.time()) - bt)}
    if genesis != SOLANA_GENESIS:
        return {"chain": "solana", "assessed": False, "node": node, "reason": f"genesis {genesis} is not mainnet-beta"}
    if node["block_age_s"] > MAX_BLOCK_AGE_S:
        return {"chain": "solana", "assessed": False, "node": node,
                "reason": f"stale node: finalized slot is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
    label, cmint, need = SOLANA_CONTROL
    _, _, _, cext = _sol_mint(cmint)
    ctl = {"token": label, "address": cmint, "ok": all(n in cext for n in need), "extensions_seen": sorted(cext)}
    if not ctl["ok"]:
        return {"chain": "solana", "assessed": False, "node": node, "control": ctl,
                "reason": "positive control failed: the reader could not see Token-2022 extensions where they exist"}
    return {"ok": True, "node": node, "slot": slot, "ctl": ctl}


def read_solana(entries, now=None):
    """Solana: genesis hash must be mainnet-beta, finalized slot fresh, PYUSD must show its Token-2022 extensions."""
    try:
        g = solana_node_gate(now)
        if not g.get("ok"):
            return g
        node, slot, ctl = g["node"], g["slot"], g["ctl"]
        tokens = []
        for e in entries:
            cslot, program, info, ext = _sol_mint(e["address"])
            dec, raw = info.get("decimals"), int(info.get("supply")) if info.get("supply") is not None else None
            md = ext.get("tokenMetadata") or {}
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": md.get("name"), "symbol": md.get("symbol"), "decimals": dec,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** dec if raw is not None and dec is not None else None,
                "owner": info.get("mintAuthority"), "expected_owner": e["expected_owner"],
                "program": program, "freeze_authority": info.get("freezeAuthority"),
                "extensions": sorted(ext),
                "permanent_delegate": (ext.get("permanentDelegate") or {}).get("delegate"),
                "transfer_hook_program": (ext.get("transferHook") or {}).get("programId"),
                "implementation_code_sha256": hashlib.sha256(json.dumps(
                    {"program": program, "extensions": sorted(ext), "hook": (ext.get("transferHook") or {}).get("programId")},
                    sort_keys=True).encode()).hexdigest(),
                "eip712_entry_points": [], "read_at_slot": cslot})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "solana", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
        return {"chain": "solana", "assessed": True, "block": slot, "rpc": SOLANA_RPC, "node": node, "control": ctl,
                "tokens": tokens, "discovery": {"status": "not searched (no search source for Solana)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "solana", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def _apt_resources(address, version):
    return {r["type"]: r["data"] for r in _get_json(f"{APTOS_API}/accounts/{address}/resources?ledger_version={version}&limit=200")}


def read_aptos(entries, now=None):
    """Aptos: chain_id must be mainnet, ledger fresh; everything read at ONE ledger version. The creator's Move modules
    are hashed (a change = an upgrade) and scanned for signature-verification primitives; the scan's control is
    0x1::account, which must be seen using ed25519."""
    try:
        li = _get_json(APTOS_API)
        version = li["ledger_version"]
        ts = int(li["ledger_timestamp"]) // 1_000_000
        node = {"chain_id": li["chain_id"], "expected_chain_id": APTOS_CHAIN_ID, "block": int(version),
                "block_timestamp": ts, "block_age_s": int((now if now is not None else time.time()) - ts)}
        if li["chain_id"] != APTOS_CHAIN_ID:
            return {"chain": "aptos", "assessed": False, "node": node, "reason": f"chain id {li['chain_id']} is not mainnet"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": "aptos", "assessed": False, "node": node,
                    "reason": f"stale node: ledger is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        label, casset = APTOS_CONTROL
        cmeta = _apt_resources(casset, version).get("0x1::fungible_asset::Metadata") or {}
        acct = _get_json(f"{APTOS_API}/accounts/0x1/module/account?ledger_version={version}")
        ctl = {"token": label, "address": casset, "metadata_readable": bool(cmeta.get("symbol")),
               "bytecode_scan_sees_ed25519": "ed25519".encode().hex() in acct.get("bytecode", "")}
        ctl["ok"] = ctl["metadata_readable"] and ctl["bytecode_scan_sees_ed25519"]
        if not ctl["ok"]:
            return {"chain": "aptos", "assessed": False, "node": node, "control": ctl,
                    "reason": "positive control failed: asset metadata or bytecode scan not working on this node"}
        tokens = []
        for e in entries:
            res = _apt_resources(e["address"], version)
            md = res.get("0x1::fungible_asset::Metadata") or {}
            cs = res.get("0x1::fungible_asset::ConcurrentSupply") or {}
            sp = res.get("0x1::fungible_asset::Supply") or {}
            raw = (cs.get("current") or {}).get("value") if cs else sp.get("current")
            raw = int(raw) if raw is not None else None
            dec = md.get("decimals")
            owner = (res.get("0x1::object::ObjectCore") or {}).get("owner")
            mods = _get_json(f"{APTOS_API}/accounts/{owner}/modules?ledger_version={version}&limit=100") if owner else []
            code = "".join(sorted(m.get("bytecode", "") for m in mods))
            used = sorted(n for n in SIG_NEEDLES if n.encode().hex() in code)
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": md.get("name"), "symbol": md.get("symbol"), "decimals": dec,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** dec if raw is not None and dec is not None else None,
                "owner": owner, "expected_owner": e["expected_owner"],
                "modules": sorted(m["abi"]["name"] for m in mods if m.get("abi")),
                "implementation_code_sha256": hashlib.sha256(code.encode()).hexdigest() if code else None,
                "signature_primitives_in_modules": used, "eip712_entry_points": [],
                "dispatchable_hooks": "0x1::fungible_asset::DispatchFunctionStore" in res})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "aptos", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
        return {"chain": "aptos", "assessed": True, "block": int(version), "rpc": APTOS_API, "node": node, "control": ctl,
                "tokens": tokens, "discovery": {"status": "not searched (no search source for Aptos)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "aptos", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def _stellar_asset(code, issuer):
    recs = _get_json(f"{STELLAR_HORIZON}/assets?asset_code={code}&asset_issuer={issuer}")["_embedded"]["records"]
    return recs[0] if len(recs) == 1 else None


def _stellar_amount(asset):
    """Every place an issued Stellar asset can sit, in stroops (7 decimals, exact integer arithmetic)."""
    def stroops(x):
        whole, _, frac = str(x).partition(".")
        return int(whole) * 10 ** 7 + int((frac + "0000000")[:7])
    b = asset["balances"]
    parts = [b["authorized"], b["authorized_to_maintain_liabilities"], b["unauthorized"],
             asset["claimable_balances_amount"], asset["liquidity_pools_amount"], asset["contracts_amount"]]
    return sum(stroops(x) for x in parts)


def stellar_signers_fingerprint(account):
    """SHA-256 of the issuer account's signer set and thresholds: who can sign for the asset."""
    body = {"signers": sorted((s["key"], s["weight"]) for s in account.get("signers", [])),
            "thresholds": account.get("thresholds")}
    return "signers-sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def read_stellar(entries, now=None):
    """Stellar (Horizon): the network passphrase must be pubnet, the latest ledger fresh, USDC readable with a
    non-zero amount. Horizon serves the CURRENT state only: the ledger is recorded before and after the readings."""
    try:
        root = _get_json(STELLAR_HORIZON + "/")
        ts = int(datetime.strptime(root["history_latest_ledger_closed_at"], "%Y-%m-%dT%H:%M:%SZ")
                 .replace(tzinfo=timezone.utc).timestamp())
        node = {"chain_id": root["network_passphrase"], "expected_chain_id": STELLAR_PASSPHRASE,
                "block": root["history_latest_ledger"], "block_timestamp": ts,
                "block_age_s": int((now if now is not None else time.time()) - ts)}
        if root["network_passphrase"] != STELLAR_PASSPHRASE:
            return {"chain": "stellar", "assessed": False, "node": node, "reason": "network passphrase is not pubnet"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": "stellar", "assessed": False, "node": node,
                    "reason": f"stale node: latest ledger is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        label, cissuer = STELLAR_CONTROL
        ca = _stellar_asset(label, cissuer)
        ctl = {"token": label, "address": cissuer, "ok": bool(ca) and _stellar_amount(ca) > 0 and "flags" in ca}
        if not ctl["ok"]:
            return {"chain": "stellar", "assessed": False, "node": node, "control": ctl,
                    "reason": "positive control failed: a known asset could not be read on this node"}
        tokens = []
        for e in entries:
            a = _stellar_asset(e["token"], e["address"])
            acct = _get_json(f"{STELLAR_HORIZON}/accounts/{e['address']}")
            raw = _stellar_amount(a) if a else None
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": acct.get("home_domain"), "symbol": a["asset_code"] if a else None, "decimals": 7,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** 7 if raw is not None else None,
                "owner": stellar_signers_fingerprint(acct), "expected_owner": e["expected_owner"],
                "flags": a["flags"] if a else None, "contract_id": a.get("contract_id") if a else None,
                "implementation_code_sha256": hashlib.sha256(json.dumps(
                    {"flags": a["flags"], "contract_id": a.get("contract_id")}, sort_keys=True).encode()).hexdigest() if a else None,
                "eip712_entry_points": []})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "stellar", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} issued by {e['address']}: asset not readable"}
        node["block_after"] = _get_json(STELLAR_HORIZON + "/")["history_latest_ledger"]
        return {"chain": "stellar", "assessed": True, "block": node["block"], "rpc": STELLAR_HORIZON, "node": node,
                "control": ctl, "tokens": tokens,
                "discovery": {"status": "not searched (no search source for Stellar)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "stellar", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


# 4-byte selectors of the EIP-712 family entry points
SELECTORS = {"DOMAIN_SEPARATOR": "3644e515", "eip712Domain": "84b0196e", "permit": "d505accf",
             "transferWithAuthorization": "e3ee160e"}
PROXY_SLOTS = {  # where proxies keep their implementation address
    "eip1967": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "zeppelinos": "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
    "slot1": "0x1",
}
# EIP-1967 BEACON proxies (OpenZeppelin BeaconProxy; the Ondo Stocks tokens are such, measured 28/09/2026): the proxy
# stores the BEACON's address, and the executing code is whatever the beacon's implementation() returns. Tried AFTER
# the direct slots above, so every contract resolved by them keeps its fingerprint unchanged (negative control).
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
BEACON_IMPL_SELECTOR = "0x5c60da1b"                                       # implementation()
# OpenZeppelin AccessControl (+ the enumerable extension): the control key of a token whose owner() reverts is the
# holder of DEFAULT_ADMIN_ROLE (0x00…00), and only when the contract ENUMERATES it and CONFIRMS it with hasRole.
DEFAULT_ADMIN_ROLE = "0" * 64
ACCESS_CONTROL_SELECTORS = {"hasRole": "91d14854", "getRoleMemberCount": "ca15c873", "getRoleMember": "9010d07c"}


# ───────────────────────── vendored hash-chain (OMEGA-style, independent) ──
def chain_hash(record_without_hash):
    blob = json.dumps(record_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def append(records, rec):
    rec = dict(rec)
    rec["prev_hash"] = records[-1]["self_hash"] if records else GENESIS
    rec["self_hash"] = chain_hash(rec)
    records.append(rec)
    return rec


def verify_chain(records):
    prev = GENESIS
    for i, r in enumerate(records):
        body = {k: v for k, v in r.items() if k != "self_hash"}
        if r["self_hash"] != chain_hash(body):
            return False, f"self_hash mismatch at #{i}"
        if r["prev_hash"] != prev:
            return False, f"link broken at #{i}"
        prev = r["self_hash"]
    return True, "PASS"


# ───────────────────────── JSON-RPC ──
class RpcError(Exception):
    pass


NETWORK_RETRIES = 1          # one retry on a TRANSPORT error only (25/09: a TLS handshake timeout on one node made a
                             # chain NOT ASSESSED for a transient fault); a node's JSON-RPC error is never retried


def rpc(chain, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(NETWORK_RETRIES + 1):
        req = urllib.request.Request(RPC[chain], data=body,
                                     headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
                out = json.loads(r.read())
            break
        except (OSError, ssl.SSLError) as ex:          # URLError, timeouts and TLS errors are OSError subclasses
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
    return out.get("result")


def eth_call(chain, to, data, block):
    """None only when the call REVERTED (the function is not there): that is an answer. Any other node error
    (rate limit, internal error) is raised, so the chain becomes NOT ASSESSED instead of 'nothing found'."""
    try:
        return rpc(chain, "eth_call", [{"to": to, "data": data}, block])
    except RpcError as ex:
        if "revert" in str(ex).lower():
            return None
        raise


def _abi_string(h):
    if not h or len(h) < 130:
        return None
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return b[64:64 + n].decode("utf-8", "replace")


def _abi_uint(h):
    return int(h, 16) if h and h != "0x" else None


def _abi_address_array(h):
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return ["0x" + b[64 + 32 * i + 12:64 + 32 * i + 32].hex() for i in range(n)]


def _abi_bytes4_array(h):
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return [b[64 + 32 * i:64 + 32 * i + 4].hex() for i in range(n)]


def read_diamond(chain, address, block):
    """EIP-2535 Diamond (JPMorgan's JLTXX is one): functions live in many facets, so the only sound question is the
    Diamond's own loupe — which selectors are registered, and in which facets. Internal control: name() must map to a
    facet. Returns None when the contract does not answer the loupe."""
    fa = eth_call(chain, address, "0x52ef6b2c", block)                # facetAddresses()
    if not fa or len(fa) < 130:
        return None
    facets = _abi_address_array(fa)
    selectors, codes = set(), []
    for f in sorted(facets, key=str.lower):
        r = eth_call(chain, address, "0xadfca15e" + "0" * 24 + f[2:], block)   # facetFunctionSelectors(address)
        selectors |= set(_abi_bytes4_array(r)) if r else set()
        codes.append(rpc(chain, "eth_getCode", [f, block]) or "0x")
    name_facet = eth_call(chain, address, "0xcdffacc6" + "06fdde03" + "0" * 56, block)   # facetAddress(name())
    return {"facets": len(facets), "selectors_registered": len(selectors),
            "loupe_control_ok": bool(name_facet) and int(name_facet, 16) != 0,
            "code_sha256": hashlib.sha256("".join(codes).encode()).hexdigest(),
            "eip712_entry_points": sorted(k for k, s in SELECTORS.items() if s in selectors)}


def locate_implementation(chain, address, block):
    """Where the EXECUTING code of `address` lives — the ONE resolver used by read_structure and read_permissioned.
    The direct proxy slots are tried first, in PROXY_SLOTS order; only when none holds a contract is the EIP-1967
    beacon slot read and the beacon asked for implementation(). A beacon whose implementation() reverts, answers
    nothing, or points to an address without code leaves the implementation UNLOCATED (the callers then report NOT
    ASSESSED, never a clean read of the proxy's own bytes). Without a proxy the executing code is the address's own."""
    proxy_code = rpc(chain, "eth_getCode", [address, block]) or "0x"
    for name, slot in PROXY_SLOTS.items():
        v = rpc(chain, "eth_getStorageAt", [address, slot, block])
        if v and int(v, 16):
            cand = "0x" + v[-40:]
            c = rpc(chain, "eth_getCode", [cand, block]) or "0x"
            if len(c) > 200:
                return {"implementation": cand, "code": c, "slot": name, "beacon": None, "proxy_code": proxy_code}
    bv = rpc(chain, "eth_getStorageAt", [address, BEACON_SLOT, block])
    if bv and int(bv, 16):
        beacon = "0x" + bv[-40:]
        r = eth_call(chain, beacon, BEACON_IMPL_SELECTOR, block)          # None = reverted: no implementation
        if r and len(r) >= 66 and int(r, 16):
            cand = "0x" + r[-40:]
            c = rpc(chain, "eth_getCode", [cand, block]) or "0x"
            if len(c) > 200:
                return {"implementation": cand, "code": c, "slot": "beacon", "beacon": beacon, "proxy_code": proxy_code}
    return {"implementation": None, "code": proxy_code, "slot": None, "beacon": None, "proxy_code": proxy_code}


def read_structure(chain, address, block):
    """Proxy/implementation shape and which EIP-712 entry points the executing code exposes."""
    loc = locate_implementation(chain, address, block)
    proxy_code, impl, impl_code, slot_name = loc["proxy_code"], loc["implementation"], loc["code"], loc["slot"]
    ds = eth_call(chain, address, "0x" + SELECTORS["DOMAIN_SEPARATOR"], block)
    if impl is None:
        dm = read_diamond(chain, address, block)
        if dm is not None and dm["loupe_control_ok"]:
            return {"proxy_code_bytes": max(len(proxy_code) // 2 - 1, 0), "implementation": f"diamond:{dm['facets']} facets",
                    "implementation_slot": "eip2535", "implementation_code_sha256": dm["code_sha256"],
                    "diamond": {"facets": dm["facets"], "selectors_registered": dm["selectors_registered"]},
                    "eip712_entry_points": dm["eip712_entry_points"], "domain_separator_answers": bool(ds and len(ds) > 2)}
    exposed = sorted(k for k, s in SELECTORS.items() if s in impl_code)
    out = {
        "proxy_code_bytes": max(len(proxy_code) // 2 - 1, 0),
        "implementation": impl,
        "implementation_slot": slot_name,
        "implementation_code_sha256": hashlib.sha256(bytes.fromhex(impl_code[2:])).hexdigest() if len(impl_code) > 2 else None,
        "eip712_entry_points": exposed,
        "domain_separator_answers": bool(ds and len(ds) > 2),
    }
    if loc["beacon"]:                      # only a beacon proxy carries this key: the other records stay as they were
        out["beacon"] = loc["beacon"]
    return out


def read_owner(chain, address, block):
    o = eth_call(chain, address, "0x8da5cb5b", block)
    return ("0x" + o[-40:]).lower() if o and len(o) >= 66 else None


def read_access_control_admin(chain, address, block, cap=8):
    """The holders of AccessControl's DEFAULT_ADMIN_ROLE, when the contract exposes the ENUMERABLE extension:
    getRoleMemberCount(0x00), then each getRoleMember(0x00, i) CONFIRMED by hasRole(0x00, member). None when the
    contract does not enumerate the role or denies a member it enumerated — then the key is not comparable, said,
    never inferred. `cap` bounds the enumeration (a count beyond it is still recorded)."""
    z = DEFAULT_ADMIN_ROLE
    n = _abi_uint(eth_call(chain, address, "0x" + ACCESS_CONTROL_SELECTORS["getRoleMemberCount"] + z, block))
    if n is None:
        return None
    members = []
    for i in range(min(n, cap)):
        m = eth_call(chain, address, "0x" + ACCESS_CONTROL_SELECTORS["getRoleMember"] + z + hex(i)[2:].rjust(64, "0"), block)
        if not m or len(m) < 66:
            return None
        member = ("0x" + m[-40:]).lower()
        h = eth_call(chain, address, "0x" + ACCESS_CONTROL_SELECTORS["hasRole"] + z + "0" * 24 + member[2:], block)
        if not h or int(h, 16) != 1:
            return None
        members.append(member)
    return {"count": n, "members": members}


def read_token(chain, address, block):
    dec = _abi_uint(eth_call(chain, address, "0x313ce567", block))
    raw = _abi_uint(eth_call(chain, address, "0x18160ddd", block))
    return {
        "owner": read_owner(chain, address, block),
        "name": _abi_string(eth_call(chain, address, "0x06fdde03", block)),
        "symbol": _abi_string(eth_call(chain, address, "0x95d89b41", block)),
        "decimals": dec,
        "total_supply_raw": str(raw) if raw is not None else None,     # exact integer, as a string
        "total_supply": (raw / 10 ** dec) if raw is not None and dec is not None else None,
    }


def node_identity(chain, now=None):
    """Which chain the URL really serves, and how fresh its latest block is. `now` is injectable (tests: no wall clock)."""
    cid = int(rpc(chain, "eth_chainId", []), 16)
    head = rpc(chain, "eth_getBlockByNumber", ["latest", False])
    ts = int(head["timestamp"], 16)
    age = int((now if now is not None else time.time()) - ts)
    return {"chain_id": cid, "expected_chain_id": CHAIN_IDS[chain], "block": head["number"], "block_timestamp": ts,
            "block_age_s": age}


def _http_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
        return json.loads(r.read())


def search_same_named(chain):
    """(status, {address: fund}) of tokens an explorer lists under the watched funds' names. A token found under
    several funds' terms is attributed to the first fund searched. Status says what was searched."""
    kind, base = DISCOVERY.get(chain, (None, None))
    if kind is None:
        return "not searched (no explorer search configured)", {}
    found, errors = {}, []
    for fund, spec in FUND_SEARCH.items():
        for term in spec["terms"]:
            try:
                if kind == "blockscout":
                    d = _http_json(f"{base}/api/v2/search?q={urllib.parse.quote(term)}")
                    hits = [it["address_hash"] for it in d.get("items", [])
                            if it.get("type") == "token" and it.get("address_hash")]
                else:
                    d = _http_json(f"{base}?term={urllib.parse.quote(term)}&filterby=0")
                    hits = [it["address"] for it in (d if isinstance(d, list) else [])
                            if str(it.get("group", "")).startswith("Tokens") and it.get("address")]
                for a in hits:
                    found.setdefault(a, fund)
            except Exception as ex:                   # the explorer failed: say so, never read it as "none found"
                errors.append(f"{term}: {type(ex).__name__}")
    status = (f"searched {kind}, first result page per term, {len(FUND_SEARCH)} funds"
              + (f" (errors: {'; '.join(errors)})" if errors else ""))
    return status, dict(sorted(found.items(), key=lambda kv: kv[0].lower()))


def read_permissioned(chain, address, block):
    """Which ERC-3643 / ERC-7943 permissioned entry points the EXECUTING code exposes, with a positive control that
    the byte scan works (it must see EIP-2612 `permit` where a permit-token exposes it). `scan_control_permit_visible`
    False means the scan cannot be trusted to report absence. Only a structural fingerprint — it never reads WHO is in
    an identity registry (that would breach the boundary)."""
    impl_code = locate_implementation(chain, address, block)["code"]     # the same resolver as read_structure
    seen = sorted(k for k, sel in PERMISSIONED_SELECTORS.items() if sel in impl_code)
    answers = {"identity_registry_answers": None, "compliance_answers": None}
    # confirm a match ANSWERS with an address, not just a byte coincidence (28/09: IBITon carries `compliance()` alone
    # with a contract address; that target's bytecode has no PUSH4 of ICompliance canTransfer, bindToken or isTokenBound,
    # and whose module it is is not established on-chain)
    for key, sel in (("identity_registry_answers", "erc3643:identityRegistry"), ("compliance_answers", "erc3643:compliance")):
        if sel in seen:
            r = eth_call(chain, address, "0x" + PERMISSIONED_SELECTORS[sel], block)
            answers[key] = bool(r and len(r) >= 66 and int(r, 16) != 0)
    return {"permissioned_interfaces": seen,
            "scan_control_permit_visible": PERMISSIONED_SCAN_CONTROL_SELECTOR in impl_code, **answers}


def read_etf_evm(chain, block, entries):
    """Each EVM ETF token at a block: supply, control key vs the issuer's recorded key, structure, permissioned
    fingerprint. A token whose symbol or supply cannot be read is reported (readable False), never dropped."""
    out = []
    for e in entries:
        t = read_token(chain, e["address"], block)
        # the CONTROL KEY: owner() when it answers; else the sole holder of AccessControl's DEFAULT_ADMIN_ROLE when
        # the contract enumerates and confirms it (IBITon, 28/09/2026); else None = not comparable, said, not faked
        key, kind, admin = t["owner"], ("owner()" if t["owner"] else None), None
        if key is None:
            admin = read_access_control_admin(chain, e["address"], block)
            if admin and len(admin["members"]) == 1:
                key, kind = admin["members"][0], "AccessControl DEFAULT_ADMIN_ROLE (sole member, hasRole confirmed)"
            elif admin and admin["members"]:
                kind = f"AccessControl DEFAULT_ADMIN_ROLE ({admin['count']} members: not a single key)"
        expected = e.get("expected_owner")
        rec = {"token": e["token"], "address": e["address"], "underlying": e["underlying"], "issuer": e["issuer"],
               "status_declared": e["status"], "status_source": e["status_source"], "provenance": e["provenance"],
               "symbol": t["symbol"], "decimals": t["decimals"], "total_supply_raw": t["total_supply_raw"],
               "total_supply": t["total_supply"], "owner": t["owner"], "control_key": key, "control_key_kind": kind,
               "expected_owner": expected, "expected_owner_kind": e.get("expected_owner_kind", "owner()" if expected else None),
               "same_owner": (key.lower() == expected.lower()) if key and expected else None}
        if admin is not None:
            rec["admin_role_members"] = admin
        if t["symbol"] is None or t["total_supply"] is None:
            rec["readable"] = False
        else:
            rec["readable"] = True
            s = read_structure(chain, e["address"], block)
            rec["implementation"] = s["implementation"]
            rec["implementation_slot"] = s["implementation_slot"]
            rec["implementation_code_sha256"] = s["implementation_code_sha256"]
            if s.get("beacon"):
                rec["beacon"] = s["beacon"]
            rec["eip712_entry_points"] = s["eip712_entry_points"]
            rec["permissioned"] = read_permissioned(chain, e["address"], block)
            if s["implementation"] is None and s["proxy_code_bytes"] < 1024:
                # the same guard as the fund layer: a small proxy whose implementation is not located is NOT ASSESSED
                rec["readable"] = False
                rec["reason"] = f"proxy of {s['proxy_code_bytes']} bytes, implementation not located"
        out.append(rec)
    return out


def scaled_ui_multiplier(ext, now):
    """Token-2022 scaledUiAmountConfig: the multiplier holders' balances are DISPLAYED with (splits, reinvested
    dividends). The effective one is newMultiplier once `now` >= newMultiplierEffectiveTimestamp, else multiplier.
    Returns (multiplier, which) or (None, None) when the mint has no such extension. `now` is injected (no wall clock
    in tests)."""
    cfg = ext.get("scaledUiAmountConfig")
    if not cfg:
        return None, None
    ts = cfg.get("newMultiplierEffectiveTimestamp")
    if ts is not None and cfg.get("newMultiplier") is not None and now >= int(ts):
        return float(cfg["newMultiplier"]), "newMultiplier"
    return float(cfg["multiplier"]), "multiplier"


def read_etf_solana(entries, now=None):
    """Each Token-2022 ETF mint (xStocks, Ondo): supply, mint/freeze authority vs the recorded issuer keys, and the set of
    Token-2022 CONTROL extensions (the permissioned surface on Solana). `total_supply` is the RAW token amount
    (supply / 10**decimals); where the mint carries scaledUiAmountConfig the amount holders SEE is that times the
    effective multiplier, recorded apart as `ui_amount` (28/09: SPYx 1.0057…, IBITon 1)."""
    now = now if now is not None else time.time()
    out = []
    for e in entries:
        try:
            slot, program, info, ext = _sol_mint(e["address"])
            dec = info.get("decimals")
            raw = int(info["supply"]) if info.get("supply") is not None else None
            mult, which = scaled_ui_multiplier(ext, now)
            amount = (raw / 10 ** dec) if raw is not None and dec is not None else None
            out.append({
                "ui_multiplier": mult, "ui_multiplier_field": which,
                "ui_amount": (amount * mult) if amount is not None and mult is not None else None,
                "token": e["token"], "address": e["address"], "underlying": e["underlying"], "issuer": e["issuer"],
                "status_declared": e["status"], "status_source": e["status_source"], "provenance": e["provenance"],
                "readable": True, "slot": slot, "program": program, "decimals": dec,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": (raw / 10 ** dec) if raw is not None and dec is not None else None,
                "mint_authority": info.get("mintAuthority"), "freeze_authority": info.get("freezeAuthority"),
                "expected_mint_authority": e["expected_mint_authority"],
                "same_mint_authority": info.get("mintAuthority") == e["expected_mint_authority"],
                "same_freeze_authority": info.get("freezeAuthority") == e["expected_freeze_authority"],
                "token2022": program == XSTOCKS_TOKEN2022,
                "transfer_hook_program": (ext.get("transferHook") or {}).get("programId"),
                "permissioned_controls": sorted(k for k in ext if k in SOLANA_CONTROL_EXTENSIONS)})
        except Exception as ex:
            out.append({"token": e["token"], "address": e["address"], "readable": False,
                        "reason": f"{type(ex).__name__}: {str(ex)[:160]}"})
    return out


def fetch_etf_signal(now=None):
    """Tokenized-ETF layer: per EVM chain, node identity + positive control (reused from the fund layer), then each
    ETF token read at the block; then the Solana (Token-2022) mints. Additive — it NEVER touches the BUIDL metric."""
    by_chain = {}
    for e in ETF_REGISTRY_EVM:
        by_chain.setdefault(e["chain"], []).append(e)
    chains = []
    for chain, entries in by_chain.items():
        try:
            g = evm_node_gate(chain, now)                          # same gate as the fund layer
            if not g.get("ok"):
                chains.append(g)
                continue
            block, ctl = g["block"], g["ctl"]
            chains.append({"chain": chain, "assessed": True, "block": int(block, 16), "control": ctl,
                           "tokens": read_etf_evm(chain, block, entries)})
        except Exception as ex:
            chains.append({"chain": chain, "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"})
    try:                                                           # Solana: the same gate as the fund layer, first
        gate = solana_node_gate(now)
        if not gate.get("ok"):
            chains.append(gate)
        else:
            sol = read_etf_solana(ETF_REGISTRY_SOLANA, now)
            chains.append({"chain": "solana", "assessed": bool(sol) and all(t.get("readable") for t in sol),
                           "block": gate["slot"], "node": gate["node"], "control": gate["ctl"], "tokens": sol})
    except Exception as ex:
        chains.append({"chain": "solana", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"})
    totals = {}
    for c in chains:
        for t in c.get("tokens", []):
            if t.get("total_supply") is not None:
                totals[t["token"]] = totals.get(t["token"], 0.0) + t["total_supply"]
    return {
        "asset_class": "tokenized ETF / equity tracker (tracks a listed ETF, per its issuer)",
        "totals": {k: round(v, 6) for k, v in sorted(totals.items())},
        "totals_meaning": "per token, sum of on-chain total supply over the chains assessed this run (a token count, NOT AUM and NOT the ETF's NAV)",
        "chains_assessed": [c["chain"] for c in chains if c.get("assessed")],
        "chains_not_assessed": [c["chain"] for c in chains if not c.get("assessed")],
        "chains": chains,
        "note": "issuer state (listed vs redemption_only) is DECLARED by the issuer with date, not measured on-chain; "
                "ERC-3643/7943 selector absence is asserted only where scan_control_permit_visible is true; elsewhere it is not assessed",
    }


def _fund_owners(fund):
    """Every control key recorded for a fund, all chains; empty when the fund exposes none (BENJI on EVM)."""
    owners = {str(e.get("expected_owner", EXPECTED_OWNER)).lower() for e in REGISTRY if e["token"] == fund
              and e.get("expected_owner", EXPECTED_OWNER)}
    return owners


def classify_unregistered(chain, address, block, fund="BUIDL"):
    """What a same-named, unregistered token looks like on-chain. Never a verdict of fraud: a shape and a reading."""
    t = read_token(chain, address, block)
    s = read_structure(chain, address, block)
    shape = {"proxy_code_bytes": s["proxy_code_bytes"], "implementation_slot": s["implementation_slot"]}
    owners = _fund_owners(fund)
    t.update({"address": address, "fund": fund, "proxy_code_bytes": s["proxy_code_bytes"],
              "implementation_slot": s["implementation_slot"],
              "securitize_shape": shape in SECURITIZE_SHAPES,
              # None = not comparable: the fund's registered contracts expose no owner()
              "same_owner": (str(t.get("owner")).lower() in owners) if owners else None})
    # A ticker alone proves nothing ("BUIDL" is older than the fund). What can be said is only this: whether the token
    # is owned by a key recorded for the fund, and whether its name carries the issuer's / fund's name.
    name = (t.get("name") or "").lower()
    t["carries_issuer_name"] = any(n in name for n in FUND_SEARCH[fund]["needle"])
    if t["same_owner"]:
        t["class"] = f"owned by a key recorded for {fund} but not in the registry: likely a new issuer deployment — check and add by hand"
    elif t["carries_issuer_name"] and t["same_owner"] is None:
        t["class"] = (f"carries the {fund} issuer's name; owner not comparable ({fund}'s registered contracts expose no "
                      "owner()): an older or other issuer deployment, a wrapper or an imitation — not told apart here")
    elif t["carries_issuer_name"]:
        t["class"] = (f"carries the {fund} issuer's name, not owned by a key recorded for {fund}: not a deployment of "
                      "the registered key (imitation, wrapper, or another product of the issuer — not told apart here)")
    else:
        t["class"] = "shares a search term only (e.g. a common ticker word): not classified"
    return t


def discover(chain, block, registered):
    status, hits = search_same_named(chain)
    known = {a.lower() for a in registered}
    # Positive control of the SEARCH, per fund registered on this chain: its registered token must be among the hits.
    # If not, the explorer cannot see that fund here and "nothing found" means nothing (25/09: BscScan returns [] for
    # every USYC term, yet USYC is on BNB Chain).
    found = {a.lower() for a in hits}
    by_fund = {}
    for e in REGISTRY:
        if e["chain"] == chain and e["address"].lower() in known and e["token"] in FUND_SEARCH:
            by_fund[e["token"]] = by_fund.get(e["token"], False) or e["address"].lower() in found
    blind = sorted(f for f, ok in by_fund.items() if not ok)
    if blind and not status.startswith("not searched"):
        status += f"; search control FAILED for {', '.join(blind)} (the registered token is not in the results: " \
                  "no finding for that fund here is meaningful)"
    out = []
    for a, fund in hits.items():
        if a.lower() in known:
            continue
        try:
            out.append(classify_unregistered(chain, a, block, fund))
        except Exception as ex:
            out.append({"address": a, "fund": fund, "class": f"unreadable: {type(ex).__name__}"})
    # kept: owned by the issuer key, or carrying BlackRock's name; tokens sharing only a search term are counted.
    # A token that could not be READ is neither (25/09: six Polygon reads failed in one cycle and silently joined the
    # "not classified" count while the council said QUIET): listed apart, and the council flags it.
    unreadable = [u["address"] for u in out if str(u.get("class", "")).startswith("unreadable")]
    kept = [u for u in out if u.get("same_owner") or u.get("carries_issuer_name")]
    return {"status": status, "unregistered": kept, "unreadable": unreadable, "search_control": by_fund,
            "other_matches_not_classified": len(out) - len(kept) - len(unreadable)}


def control_ok(chain, block):
    """The reader must SEE EIP-712 on a token that has it, on this node, at this block."""
    label, addr = CONTROLS[chain]
    s = read_structure(chain, addr, block)
    ok = "DOMAIN_SEPARATOR" in s["eip712_entry_points"] and s["domain_separator_answers"]
    return {"token": label, "address": addr, "ok": ok, "eip712_entry_points": s["eip712_entry_points"]}


def evm_node_gate(chain, now=None):
    """Node identity, freshness and the EIP-712 positive control for one EVM chain — the gate SHARED by the fund
    layer (read_chain) and the ETF layer (fetch_etf_signal), so the guard is written and mutation-tested once.
    Returns {"ok": True, "node", "block", "ctl"} when the chain may be read, else a NOT-ASSESSED dict."""
    node = node_identity(chain, now)
    if node["chain_id"] != node["expected_chain_id"]:
        return {"chain": chain, "assessed": False, "node": node,
                "reason": f"the URL serves chain id {node['chain_id']}, not {node['expected_chain_id']}"}
    if node["block_age_s"] > MAX_BLOCK_AGE_S:
        return {"chain": chain, "assessed": False, "node": node,
                "reason": f"stale node: latest block is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
    block = node["block"]
    ctl = control_ok(chain, block)
    if not ctl["ok"]:
        return {"chain": chain, "assessed": False, "block": int(block, 16), "control": ctl,
                "reason": "positive control failed: the reader could not see EIP-712 where it exists"}
    return {"ok": True, "node": node, "block": block, "ctl": ctl}


def read_chain(chain, entries, now=None, discovery=True):
    """One chain: node identity (chain id, block age), positive control, then every registered token and, if
    enabled, same-named unregistered tokens. Any failure of the node checks makes the chain NOT ASSESSED."""
    try:
        g = evm_node_gate(chain, now)
        if not g.get("ok"):
            return g
        node, block, ctl = g["node"], g["block"], g["ctl"]
        tokens = []
        for e in entries:
            t = read_token(chain, e["address"], block)
            if t["symbol"] is None or t["total_supply"] is None:
                return {"chain": chain, "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
            t.update(read_structure(chain, e["address"], block))
            if t["implementation"] is None and t["proxy_code_bytes"] < 1024:   # (a Diamond answers its loupe: not here)
                # a small proxy whose implementation this reader cannot locate: the EIP-712 scan would read the proxy
                # itself and report "absent" (NEMESIS 25/09) — not assessed instead of a false clean
                return {"chain": chain, "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: proxy of {t['proxy_code_bytes']} bytes, implementation not located"}
            t.update({"token": e["token"], "address": e["address"], "provenance": e["provenance"],
                      "expected_owner": e.get("expected_owner", EXPECTED_OWNER)})
            tokens.append(t)
        found = discover(chain, block, [e["address"] for e in entries]) if discovery else {"status": "disabled", "unregistered": []}
        return {"chain": chain, "assessed": True, "block": int(block, 16), "rpc": RPC[chain], "node": node,
                "control": ctl, "tokens": tokens, "discovery": found}
    except Exception as ex:                          # network, TLS, JSON: the chain is not assessed, and says why
        return {"chain": chain, "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def fetch_signal(now=None, discovery=True):
    """Real readings for every registered chain. `metric` = total BUIDL supply over the ASSESSED chains (kept as the
    tuned series); `totals` = the same sum for every watched token, over the chains assessed this run."""
    by_chain = {}
    for e in REGISTRY:
        by_chain.setdefault(e["chain"], []).append(e)
    chains = [read_chain(c, es, now, discovery) for c, es in by_chain.items()]
    chains.append(read_solana([e for e in NONEVM_REGISTRY if e["chain"] == "solana"], now))
    chains.append(read_aptos([e for e in NONEVM_REGISTRY if e["chain"] == "aptos"], now))
    chains.append(read_stellar([e for e in NONEVM_REGISTRY if e["chain"] == "stellar"], now))
    totals = {}
    for c in chains:
        for t in c.get("tokens", []):
            if t.get("total_supply") is not None:
                totals[t["token"]] = totals.get(t["token"], 0.0) + t["total_supply"]
    assessed = [c["chain"] for c in chains if c.get("assessed")]
    return {
        "metric": round(totals.get("BUIDL", 0.0), 6),
        "metric_meaning": "sum of BUIDL total supply over the assessed chains, EVM + Solana + Aptos (not AUM; BUIDL-I excluded)",
        "totals": {k: round(v, 6) for k, v in sorted(totals.items())},
        "totals_meaning": "per token, sum of total supply over the chains assessed this run (not AUM, not NAV)",
        "chains_assessed": assessed,
        "chains_not_assessed": [c["chain"] for c in chains if not c.get("assessed")],
        "chains": chains,
        "source": "public JSON-RPC nodes (publicnode.com), Solana/Aptos public RPC, Stellar Horizon; block recorded per chain",
    }


def snapshot():
    """One observation: real signal + UTC timestamp, ready to be chained."""
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "domain": "rwawatch",
            "signal": fetch_signal(), "etf_signal": fetch_etf_signal()}


if __name__ == "__main__":
    recs = []
    append(recs, snapshot())
    ok, msg = verify_chain(recs)
    print(json.dumps(recs[-1], ensure_ascii=False, indent=2))
    print("chain:", msg)
