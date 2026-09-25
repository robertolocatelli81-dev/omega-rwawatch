# Consegna per Fable 5 — omega-rwawatch + esempio AladdinSDK (25/09/2026)

Scritta da Opus 5.5 su ordine di Roberto («salva per far poi verificare a Fable 5»). Niente è pubblicato: repo
locale senza remote, nessun push, timer `deploy/` non attivo. GitHub (repo PRIVATO) solo dopo il tuo verdetto.

**Chiedo il verdetto contrario.** Tutte le misure qui sotto le ho fatte io, con banchi e mutazioni scelti da me:
è la condizione in cui un verificatore dà ragione a chi l'ha scritto. Le debolezze che conosco sono elencate in fondo;
cerca soprattutto quelle che non conosco.

## Cosa c'è

| Commit | Contenuto |
|--------|-----------|
| `ba0008a` → `9562049` | BUIDL su 6 EVM, poi identità del nodo, co-firma ML-DSA-65, scoperta imitazioni, Solana e Aptos (già descritti nella memoria del 25/09 mattina) |
| `20df497` | JLTXX (Diamond EIP-2535 letto via loupe), BENJI (8 catene, Base e Stellar nuove), USYC; supply per token; match illeggibili segnalati |
| `4562cf9` | ricerca imitazioni per i 4 fondi, owner confrontato per fondo («non confrontabile» per BENJI EVM); **MONY registrato** |
| `79f464d` | controllo positivo della RICERCA per fondo; termine BENJI corretto; 3 test che non potevano fallire ora falliscono |

Esempio AladdinSDK: `~/progetti/omega-evidence`, branch `example/aladdinsdk-export` (`768a0ff`, `d1334b8`), non
pubblicato.

## Come rimisurare (tutto)

```bash
cd ~/progetti/omega-rwawatch
python3 tests/test_rwawatch.py                                   # atteso: 36 test OK, senza rete
mkdir -p /tmp/abl/home && python3 tools/ablate_guards.py /tmp/abl   # atteso: "mutations surviving: 0 of 27"
PYTHONPATH=~/progetti/omega-evidence python3 rwawatch_orchestrator.py   # ~8 min, rete; scrive memoria + pacco
cd ~/progetti/omega-evidence
P=$(ls -t ~/progetti/omega-rwawatch/evidence/rwawatch_2*.json | grep -v sig | head -1)
python3 -m omega_evidence $P --ledger ~/progetti/omega-rwawatch/evidence/rwawatch_evidence.ledger.jsonl \
    --trust-store ~/progetti/omega-rwawatch/evidence/trust.jsonl --require-pq
node verifiers/js/oeverify.mjs $P --ledger … --trust-store … --require-pq
# AladdinSDK (venv con aladdinsdk 2.0.0b10 nello scratchpad della sessione 25/09: aladdin_venv; altrimenti pip install aladdinsdk==2.0.0b10)
cd ~/progetti/omega-evidence/examples/aladdinsdk-export && <venv>/bin/python run_scenarios.py /tmp/aladdin_w
```

Nota: `omega_evidence` NON è installato nel python3 di sistema; senza `PYTHONPATH` il ciclo gira ma dice «no signed
pack» (onesto, non un errore). Il `PYTHONPATH` punta al tree del branch attualmente estratto in omega-evidence.

## Affermazioni del README da verificare (misurate da me il 25/09)

1. Ciclo 15:07 UTC: 10/10 catene valutate; pacco PASS + `pq_protected` con Python e con Node; una cifra cambiata →
   FAIL in entrambi (`pack-sha3` e `pq-signature` in Python).
2. Secondo provider, stesso blocco (≈15:05 UTC): 16/16 letture EVM identiche (totalSupply + owner, chainId dell'URL
   alternativo corretto); Solana 3/3 (supply + mint authority); Aptos 2/2 alla stessa ledger version (fullnode
   aptoslabs; `aptos-rest.publicnode.com` rispondeva HTTP 500); Stellar supply e impronta firmatari identiche (LOBSTR).
3. Totali (ciclo 14:42): BUIDL ≈ 2.033,3 M; BUIDL-I ≈ 239,7 M; JLTXX ≈ 849,2 M; BENJI ≈ 668,0 M; USYC ≈ 2.111,3 M;
   MONY ≈ 102,8 M (ciclo 15:07).
4. **USYC è l'unico token seguito con entry point EIP-712** (`DOMAIN_SEPARATOR`, `permit` su Ethereum e BNB). Perimetro:
   i contratti EVM seguiti; sulle catene non-EVM la domanda EIP-712 non si pone.
5. BENJI EVM: nessun `owner()` e slot admin EIP-1967 vuoto su tutte e 5 → chiave NON verificata (dichiarato).
6. MONY: trovato dalla ricerca perché di proprietà della chiave registrata per JLTXX; il comunicato J.P. Morgan del
   15/12/2025 (sha256 HTML 3dc77e38…) contiene solo quell'indirizzo. Roberto: «tienilo».
7. Ricerca: BscScan restituisce `[]` per ogni termine USYC → USYC non ricercabile su BNB («search control FAILED»).
   Reperti non registrati, prima pagina: vedi README («Search for the other funds»).
8. Esempio AladdinSDK: 11 casi × CSV e JSON = tabella del README; strati che falliscono: hash aggiornato →
   `pack-sha3`; tutto ricostruito → `producer-signature`; trust store di altra chiave → `trusted-signer`.

## Difetti trovati e corretti oggi (verifica che la correzione sia vera, non cosmetica)

- 6 letture Polygon fallite finivano fra i «non classificati» con voto QUIET → ora lista `unreadable` + ELEVATED.
- La ricerca non aveva controllo positivo (BscScan cieco su USYC; «Franklin OnChain» non trovava mai il BENJI
  ufficiale) → controllo per fondo, ELEVATED se la vista si perde.
- 3 mutazioni sopravvivevano: revert su `totalSupply` non coperto; test retry tautologico (`NETWORK_RETRIES + 1`);
  nota «tuned» registrata quando la soglia era invariata.
- Nel README: iBENJI scritto «solo BNB» (la pagina lo elenca anche su Ethereum); due orari scritti senza orologio.

## Debolezze che conosco (attaccale, e cerca le altre)

1. **Le 27 mutazioni le ho scelte io.** Aggiungine di tue: una guardia che non ho pensato di mutare è una guardia
   che nessuno ha provato.
2. **I test usano un nodo finto scritto da me** (FakeNode, fake Horizon/Solana/Aptos): codificano le mie ipotesi sul
   comportamento dei nodi veri.
3. **Stellar:** Horizon serve solo lo stato corrente; registro il ledger prima e dopo, ma le letture non sono a un
   ledger fissato come sulle EVM.
4. **Solana:** ogni mint è letto a `finalized`, non necessariamente allo stesso slot.
5. **Doppio conteggio fra catene** (bridge lock-and-mint) NON escluso: i totali sono somme, non AUM.
6. **La soglia di movimento** è tarata sulla serie BUIDL e applicata a tutti i token: scelta arbitraria.
7. **Ricerca:** solo prima pagina per termine; Avalanche, Base e le non-EVM non cercate; MONY non ha voci proprie in
   `FUND_SEARCH` (è trovato sotto i termini JLTXX), quindi per MONY il controllo della ricerca non è calcolato.
8. **Classificazione degli omonimi:** «non è un deployment della chiave registrata» non distingue imitazione, wrapper,
   vecchia versione o altro prodotto dell'emittente — il testo lo dice, controlla che lo dica ovunque.
9. **Il primo ciclo dopo un'aggiunta al registro è sempre ELEVATED** («not in the previous cycle»): voluto, ma
   verifica che non mascheri altro.
10. **Provenienza:** gli hash delle pagine ufficiali sono dell'HTML scaricato il 25/09; le pagine cambiano.

## Decisioni che restano a Roberto (dopo il tuo verdetto)

- repo GitHub privato (ordine: solo dopo Fable); eventuale pubblico;
- attivare il timer (ciclo ~8 min);
- se pubblicare l'esempio AladdinSDK (branch di omega-evidence).
