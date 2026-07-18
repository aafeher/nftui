# nftui

[English](README.md) · [Magyar](README.hu.md) · [Español](README.es.md) · [Português (BR)](README.pt-BR.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · **Italiano**

[![CI](https://img.shields.io/github/actions/workflow/status/aafeher/nftui/ci.yml?branch=main&label=CI)](https://github.com/aafeher/nftui/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/aafeher/nftui/codeql.yml?branch=main&label=CodeQL)](https://github.com/aafeher/nftui/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/aafeher/nftui/graph/badge.svg)](https://codecov.io/gh/aafeher/nftui)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/aafeher/nftui/badge)](https://scorecard.dev/viewer/?uri=github.com/aafeher/nftui)
[![Latest release](https://img.shields.io/github/v/release/aafeher/nftui)](https://github.com/aafeher/nftui/releases/latest)
[![License: MIT](https://img.shields.io/github/license/aafeher/nftui)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/aafeher/nftui)](go.mod)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-blue)](#requisiti)
[![Downloads](https://img.shields.io/github/downloads/aafeher/nftui/total)](https://github.com/aafeher/nftui/releases)

`nftui` è un'interfaccia utente da terminale (TUI) per gestire `nftables` su
Linux. Naviga l'insieme di regole attivo, modifica le regole con editor
strutturati completi per ogni tipo di condizione e azione, e applica le
modifiche al kernel — senza mai toccare direttamente la CLI di `nft`.

Scritto in Go con il framework
[Bubble Tea](https://github.com/charmbracelet/bubbletea). Parla con il kernel
via netlink attraverso la libreria
[`google/nftables`](https://github.com/google/nftables).

## Funzionalità

### Navigazione e gestione dell'insieme di regole

- Vista ad albero di tutte le tabelle e catene con dati vivi letti dal
  kernel. Lo scheletro (tabelle, catene, set, oggetti con nome) viene reso
  subito all'avvio; i conteggi delle regole per catena si riempiono in modo
  asincrono, così un insieme di regole con molte catene resta interattivo
  mentre gli elenchi di regole arrivano in background (ogni riga di catena
  mostra brevemente `[loading rules...]` finché la sua lettura non arriva).
- Elenco delle regole per catena con resa leggibile di ogni espressione
  analizzata. L'elenco è a finestra — solo le regole che stanno sullo schermo
  vengono serializzate e disegnate, quindi scorrere una catena con più di
  1000 regole costa quanto una con 10. Il filtro in linea (`/`) memorizza in
  cache il testo minuscolo di ogni regola al primo confronto, così le
  battute successive restano reattive anche su catene grandi.
- Vista di dettaglio per regola organizzata in schede per categoria di
  condizione.
- CRUD completo su tabelle, catene e regole: creare, rinominare / modificare
  proprietà, eliminare (con conferma), riordinare le regole su / giù
  all'interno di una catena, inserire prima / accodare in fondo.

### Editor di regole — condizioni supportate

| Categoria | Corrispondenze |
|-----------|----------------|
| **CT (conntrack)** | state, direction, status, mark, secmark, expiration, helper, l3proto, protocol, proto-src, proto-dst, labels, eventmask, ip saddr / daddr, bytes, packets, avgpkt (con direzione), zone, count |
| **Intestazione IPv4** | saddr, daddr (CIDR), protocol, ttl, length, dscp, version, hdrlength, id, frag-off, checksum |
| **Intestazione IPv6** | saddr, daddr (CIDR), length, nexthdr, hoplimit, version, dscp (6 bit), flowlabel (20 bit) |
| **TCP** | sport, dport, sequence, ackseq, flags (MultiSelect), window, checksum, urgptr, doff |
| **UDP / UDPLITE** | sport, dport, length, checksum |
| **SCTP** | sport, dport, vtag, checksum, **chunk** (corrispondenza per tipo di chunk secondo RFC 4960: data / init / init-ack / sack / heartbeat / heartbeat-ack / abort / shutdown / shutdown-ack / error / cookie-echo / cookie-ack / ecne / cwr / shutdown-complete / auth / asconf-ack / i-data / forward-tsn / asconf / i-forward-tsn — sono supportate sia la semplice presenza sia le restrizioni per sotto-campo di ciascun tipo: il Select del tipo di chunk guida un Select di sotto-campo (`tsn` / `stream` / `ssn` / `ppid` per DATA; `init-tag` / `a-rwnd` / `os` / `mis` / `init-tsn` per INIT; `cum-tsn-ack` / `a-rwnd` / `num-gap-ack-blocks` / `num-dup-tsns` per SACK; ecc.) più un campo valore codificato big-endian nella larghezza corrispondente di 1 / 2 / 4 byte) |
| **Meta (interfaccia)** | iifname, oifname, iif, oif, iiftype, oiftype, iifgroup, oifgroup |
| **Meta (proto / socket / pacchetto)** | length, protocol (EtherType), nfproto, l4proto, mark, priority, skuid, skgid, cgroup, rtclassid, pkttype, cpu |

### Editor di regole — azioni supportate

- **Verdict**: `accept`, `drop`, `return`, `jump <chain>`, `goto <chain>` —
  con campo per il nome della catena per le destinazioni di jump / goto.
- **Reject**: `with icmp type`, `with icmpx type`, `with tcp reset` —
  sensibile alla famiglia (il Select del tipo ICMP cambia per tabelle ip /
  ip6 / inet / bridge).
- **Log**: prefix, level (emerg…debug), gruppo NFLOG, snaplen,
  queue-threshold — con convalida prima del salvataggio contro le
  combinazioni rifiutate dal kernel (p. es. `level` vietato in modalità
  NFLOG).
- **Counter**: modifica i conteggi di pacchetti e byte di un contatore
  anonimo (uso tipico: azzerarlo).
- **Limit**: rate, unit (second/minute/hour/day/week), burst, type
  (packets/bytes), over.

### UX dell'editor

- Ogni scheda raggruppa campi correlati; **Tab** / **Shift+Tab** sposta il
  focus tra i sotto-campi.
- I campi modificati vengono evidenziati; un campo svuotato rimuove la
  corrispondenza sottostante.
- **F2** convalida e applica tutte le modifiche via netlink
  (`NLM_F_REPLACE`).
- Una riga di aiuto a piè di pagina elenca sempre tutte le scorciatoie
  disponibili nella vista corrente.

## Requisiti

- **Linux** con un kernel con supporto `nftables`.
- **Go 1.25+** per compilare dai sorgenti.
- **`CAP_NET_ADMIN`** a runtime (esegui via `sudo` o concedi la capability
  con `setcap`).
- Un terminale di almeno **80x24** caratteri. Al di sotto, nftui mostra un
  invito a ridimensionare invece di un layout compresso.

Il runtime **non** richiede la CLI `nft` per il percorso principale di
lettura / modifica / scrittura — la comunicazione è diretta via netlink. Il
binario `nft` è usato solo da poche operazioni mirate in cui passare per la
CLI è più sicuro che ricostruire lo stato del kernel (rinominare tabelle,
ricreare catene base).

## Installazione

```bash
git clone https://github.com/aafeher/nftui.git
cd nftui
go build -o nftui .
```

### Pacchetti precompilati

Ogni [release](https://github.com/aafeher/nftui/releases) allega pacchetti
nativi per `amd64` e `arm64`, tutti costruiti dallo stesso binario degli
archivi ed elencati in `checksums.txt` (così la firma cosign copre anche
loro):

| Formato | Distribuzioni | Installazione |
|---------|---------------|---------------|
| `.deb` | Debian / Ubuntu | `sudo apt install ./nftui_<ver>_linux_amd64.deb` |
| `.rpm` | Fedora / RHEL / openSUSE | `sudo dnf install ./nftui_<ver>_linux_amd64.rpm` |
| `.apk` | Alpine | `sudo apk add --allow-untrusted ./nftui_<ver>_linux_amd64.apk` |
| `.pkg.tar.zst` | Arch | `sudo pacman -U ./nftui_<ver>_linux_amd64.pkg.tar.zst` |
| `.ipk` | OpenWrt (opkg) | `opkg install ./nftui_<ver>_linux_amd64.ipk` |

Ogni pacchetto installa `nftui` in `/usr/bin`, la pagina di manuale in
`/usr/share/man/man1`, e dichiara la dipendenza di runtime `nftables`. I
binari sono statici (senza CGO), quindi girano allo stesso modo su sistemi
glibc e musl. OpenWrt sta migrando da `opkg` ad `apk`: sulle architetture
compatibili l'`.apk` dovrebbe servire l'OpenWrt più recente basato su apk,
mentre l'`.ipk` copre le versioni opkg esistenti. I router di altre
architetture (mips, armv7) sono fuori portata — lì compila dai sorgenti.

**Arch / AUR:** il `.pkg.tar.zst` della release si installa direttamente con
`pacman -U`, senza bisogno dell'AUR. nftui non pubblica da sé sull'AUR; un
manutentore della comunità è benvenuto ad adottare il
[`packaging/aur/PKGBUILD`](packaging/aur/PKGBUILD) di riferimento (un
pacchetto `-bin` sul tarball della release).

**Gentoo:** il repository è un modulo Go standard, quindi
`go build -o nftui .` è la via più semplice. Due ebuild di riferimento
mantenibili dalla comunità sono forniti per un overlay locale:
[`nftui-1.2.0.ebuild`](packaging/gentoo/nftui-1.2.0.ebuild) compila dai
sorgenti via `go-module.eclass`, e
[`nftui-bin-1.2.0.ebuild`](packaging/gentoo/nftui-bin-1.2.0.ebuild) installa
il binario precompilato della release; installa l'uno o l'altro (condividono
`/usr/bin/nftui` e si bloccano a vicenda). Vedi
[`packaging/gentoo/README.md`](packaging/gentoo/README.md) per la
configurazione dell'overlay. nftui non mantiene una voce Portage / GURU.

### Nix flake

Il repository fornisce un [`flake.nix`](flake.nix) con un pacchetto
`buildGoModule` per `x86_64-linux` e `aarch64-linux`, una `devShell` che
rispecchia la toolchain della CI, e un `apps.default` eseguibile:

```bash
nix build              # compila in ./result/bin/nftui (+ pagina di manuale)
nix run                # compila ed esegue (serve CAP_NET_ADMIN a runtime)
nix develop            # strumenti: go, gopls, goreleaser, nftables, mandoc
```

Al primo `nix build`, il `vendorHash` è impostato di proposito a
`lib.fakeHash` — Nix stampa il vero `sha256-…` nell'errore e l'utente lo
incolla in `flake.nix` (rifissalo a ogni cambiamento di `go.sum`). Questo
mantiene indipendenti le release binarie (Goreleaser) e le build Nix: il
percorso Nix non blocca la pubblicazione delle release.

### Docker

Un [`Dockerfile`](Dockerfile) costruisce un'immagine piccola (~17 MB) che
include la CLI `nft(8)` di cui nftui ha bisogno a runtime:

```bash
docker build -t nftui:local .
# build con versione (imposta `nftui --version`):
docker build -t nftui:1.2.0 --build-arg VERSION=1.2.0 .
```

nftui gestisce l'insieme di regole dell'**host**, quindi il container ha
bisogno del namespace di rete dell'host, della capability `NET_ADMIN` e di
un TTY interattivo:

```bash
docker run --rm -it --network host --cap-add NET_ADMIN nftui:local
```

Le opzioni passano dirette, p. es. `… nftui:local --read-only`.

Un [`docker-compose.yml`](docker-compose.yml) collega le stesse opzioni. Usa
`run` (non `up`) perché la TUI riceva un TTY reale:

```bash
docker compose run --rm nftui
```

Il container gira come root e si affida a `--cap-add NET_ADMIN` più il
confine del container per l'isolamento; con `--network host` modifica
l'nftables dell'host — la stessa impronta di privilegi dell'eseguire il
binario sull'host (vedi
[Modello di privilegi e irrobustimento del deployment](#modello-di-privilegi-e-irrobustimento-del-deployment)).

### Esecuzione

Con `sudo`:

```bash
sudo ./nftui
```

…oppure concedi al binario la capability necessaria una sola volta:

```bash
sudo setcap cap_net_admin=ep ./nftui
./nftui
```

### Installazione della pagina di manuale (facoltativa)

```bash
sudo install -m 0644 man/nftui.1 /usr/share/man/man1/               # inglese
sudo install -m 0644 man/hu/nftui.1 /usr/share/man/hu/man1/         # ungherese (facoltativa)
sudo install -m 0644 man/es/nftui.1 /usr/share/man/es/man1/         # spagnolo (facoltativa)
sudo install -m 0644 man/pt_BR/nftui.1 /usr/share/man/pt_BR/man1/   # portoghese brasiliano (facoltativa)
sudo install -m 0644 man/fr/nftui.1 /usr/share/man/fr/man1/         # francese (facoltativa)
sudo install -m 0644 man/de/nftui.1 /usr/share/man/de/man1/         # tedesco (facoltativa)
sudo install -m 0644 man/it/nftui.1 /usr/share/man/it/man1/         # italiano (facoltativa)
sudo mandb        # se il tuo sistema usa man-db (Debian / Ubuntu / Fedora …)
man nftui         # poi è disponibile ovunque
```

Un `man` sensibile alla locale sceglie la pagina tradotta in base a `$LANG` /
`$LC_MESSAGES` (p. es. `LANG=it_IT.UTF-8 man nftui`). Anteprima dall'albero
dei sorgenti senza installare:

```bash
man -l man/nftui.1          # inglese
man -l man/it/nftui.1       # italiano
man -l man/fr/nftui.1       # francese
man -l man/de/nftui.1       # tedesco
man -l man/es/nftui.1       # spagnolo
man -l man/pt_BR/nftui.1    # portoghese brasiliano
man -l man/hu/nftui.1       # ungherese
```

## Opzioni da riga di comando

| Opzione | Descrizione |
|---------|-------------|
| `--table <name>` | Limita l'albero a una singola tabella — le sue catene, i suoi set e gli oggetti con nome. L'abbinamento è per nome in tutte le famiglie, quindi `--table filter` includerà sia `inet filter` sia `ip filter` se esistono entrambe. Un nome sconosciuto termina prima dell'avvio della TUI, mostrando l'elenco delle tabelle disponibili. |
| `--config <file>` | Applica l'insieme di regole nftables dato via `nft -f <file>` **prima** dell'avvio della TUI. **Questo muta l'insieme di regole in esecuzione** — il file può contenere `flush ruleset`. Usalo per predisporre uno stato noto per i test. Viene risolto prima di `--table`, così lo stato del kernel dopo il caricamento è ciò che `--table` convalida. |
| `--read-only` | Disattiva ogni percorso di scrittura: nessun add / insert / move / delete / edit / save di regole, nessun create / delete di catene / tabelle / set, nessun azzeramento di contatori. I tasti bloccati si attenuano nel piè di pagina (secondo l'invariante di completezza del piè di pagina) e un marcatore `[READ-ONLY MODE]` (in italiano `[SOLA LETTURA]`) accompagna il titolo di ogni vista principale. Utile per navigazione sicura, audit, o abbinato a `--config` per ispezionare una fixture senza rischio di modifiche accidentali. |
| `--lang <code>` | Imposta la lingua dell'interfaccia, p. es. `en`, `hu`, `es`, `pt-BR`, `fr`, `de` o `it`. Scavalca l'ambiente di locale (`LC_ALL` / `LC_MESSAGES` / `LANG`). Un valore assente o non supportato ricade sul rilevamento automatico della locale e infine sull'inglese. Sono accettate solo le lingue per cui nftui include un catalogo — attualmente **inglese**, **ungherese**, **spagnolo**, **portoghese brasiliano**, **francese**, **tedesco** e **italiano**. Vedi [Lingua / localizzazione](#lingua--localizzazione). |
| `--help` (anche `-h`) | Stampa l'elenco completo delle opzioni con descrizioni di una riga ed esempi d'uso, poi termina. Va su stdout (quindi puoi rediligerla a `less`); un `--help` esplicito termina con 0. Le opzioni non valide emettono lo stesso testo d'uso su stderr e terminano con 2. |
| `--version` | Stampa `nftui <versione>` su stdout e termina con 0. La versione viene iniettata alla build di release; un binario compilato dai sorgenti riporta la versione di modulo dal build-info di Go, oppure `dev` per un semplice `go build`. |

Esempi:

```bash
sudo ./nftui --table filter                              # mostra solo la/le tabella/e chiamata/e 'filter'
sudo ./nftui --table missing                             # termina: "table 'missing' not found. Available tables: …"
sudo ./nftui --config examples/example-nftables-01.conf  # carica la fixture di test manuale e la naviga
sudo ./nftui --read-only                                 # navigazione sicura — ogni tasto di scrittura è attenuato e inerte
sudo ./nftui --config new.conf --table filter            # applica new.conf e limita la vista alla sua tabella 'filter'
./nftui --version                                        # stampa la versione e termina (nessun privilegio richiesto)
```

Senza `--config`, l'insieme di regole in esecuzione resta intatto. Senza
`--table`, vengono mostrate tutte le tabelle. Senza `--read-only`, tutte le
azioni CRUD sono disponibili.

## Lingua / localizzazione

L'interfaccia di nftui è localizzata. La lingua viene risolta una sola volta
all'avvio, in quest'ordine:

1. l'opzione `--lang <code>` (p. es. `--lang it`);
2. altrimenti l'ambiente di locale POSIX — `LC_ALL`, poi `LC_MESSAGES`, poi
   `LANG` (i suffissi `.codeset` / `@modifier` sono ignorati, e `C` / `POSIX`
   significano inglese);
3. altrimenti l'inglese.

Un codice assente o non supportato ricade sul rilevamento automatico e
infine sull'inglese, quindi nftui parte sempre in una lingua per cui ha un
catalogo. La scelta è fissata per la sessione — non c'è cambio di lingua
dentro l'applicazione.

**Lingue supportate:** inglese (fonte), ungherese (`hu`), spagnolo (`es`),
portoghese brasiliano (`pt-BR`), francese (`fr`), tedesco (`de`) e italiano
(`it`). L'inglese è la locale *fonte*: ogni testo della TUI rivolto
all'utente viene risolto attraverso i cataloghi di messaggi incorporati
(`i18n/locales/*.json`), con l'inglese come ripiego per qualsiasi chiave
mancante.

**Ambito:** la TUI interattiva — l'albero, i pannelli, le viste di regola /
catena / set, i dialoghi di creazione / modifica, l'editor di regole, i piè
di pagina e le conferme — è completamente localizzata. Il vocabolario
proprio di nftables (nomi di attributo come `type` / `hook` / `policy`, i
verdict, le parole chiave delle espressioni e qualsiasi sintassi di regola
copiabile) resta in inglese in ogni lingua, così ciò che leggi continua a
coincidere con ciò che `nft` accetta. L'output di `--help` / `--version` è
solo in inglese — viene consumato fuori dalla TUI, e `--help` è risolto
prima della selezione della lingua. La pagina di manuale `nftui(1)` è
distribuita in inglese ([`man/nftui.1`](man/nftui.1)), ungherese
([`man/hu/nftui.1`](man/hu/nftui.1)), spagnolo
([`man/es/nftui.1`](man/es/nftui.1)), portoghese brasiliano
([`man/pt_BR/nftui.1`](man/pt_BR/nftui.1)), francese
([`man/fr/nftui.1`](man/fr/nftui.1)), tedesco
([`man/de/nftui.1`](man/de/nftui.1)) e italiano
([`man/it/nftui.1`](man/it/nftui.1)); questo README esiste anche in
[inglese](README.md), [ungherese](README.hu.md), [spagnolo](README.es.md),
[portoghese brasiliano](README.pt-BR.md), [francese](README.fr.md) e
[tedesco](README.de.md).

```bash
sudo ./nftui --lang it             # interfaccia in italiano
sudo ./nftui --lang fr             # interfaccia in francese
sudo ./nftui --lang de             # interfaccia in tedesco
LANG=it_IT.UTF-8 sudo -E ./nftui   # italiano dall'ambiente di locale
sudo ./nftui --lang en             # forza l'inglese qualunque sia la locale
```

## Modello di privilegi e irrobustimento del deployment

nftui legge e scrive l'insieme di regole nftables del kernel via netlink, il
che richiede la capability **`CAP_NET_ADMIN`**. Non ha **alcuna
autenticazione o autorizzazione propria**: qualsiasi utente in grado di
avviare nftui con quella capability può riscrivere il firewall. nftui è
quindi sicuro solo quanto il modo in cui concedi quel privilegio — concedilo
troppo largamente e il binario diventa un *confused deputy*. Imponi il
controllo degli accessi a livello di SO. Si raccomandano due schemi.

### Consigliato: `sudo` con una regola ristretta

Esegui nftui tramite `sudo` e limita chi può farlo. Crea un gruppo dedicato
(p. es. `nftadm`), aggiungi gli operatori fidati e aggiungi una regola con
`visudo`:

```sudoers
# /etc/sudoers.d/nftui  (modificalo con: visudo -f /etc/sudoers.d/nftui)
# Lascia che il gruppo nftadm esegua nftui come root — e nient'altro.
%nftadm ALL=(root) /usr/local/bin/nftui
```

- Usa il **percorso assoluto**, così un `nftui` diverso più avanti nel
  `PATH` non può essere sostituito.
- Mantieni la richiesta di password (niente `NOPASSWD`) per l'uso
  interattivo: `sudo` scrive una voce nel registro di autenticazione a ogni
  invocazione, dandoti una traccia di chi-e-quando.
- Gli operatori eseguono quindi `sudo nftui`. nftui legge `SUDO_USER`, così
  con il [registro di audit](#registro-di-audit) attivo ogni modifica
  applicata registra l'umano dietro `sudo`, non solo `root`.

Per un ruolo di sola lettura / navigazione, concedi a un gruppo più ampio
soltanto la forma `--read-only`. `sudo` confronta il comando **e** i suoi
argomenti esattamente, quindi questa regola permette
`sudo nftui --read-only` ma non il `sudo nftui` senza restrizioni:

```sudoers
%nftview ALL=(root) /usr/local/bin/nftui --read-only
```

### Alternativa: un binario `setcap` ristretto per gruppo

Se devi lavorare senza `sudo` (p. es. automazione), concedi la capability al
file ma limita **chi può eseguirlo** — non lasciarlo mai eseguibile da
tutti:

```bash
sudo chown root:nftadm /usr/local/bin/nftui
sudo chmod 750         /usr/local/bin/nftui   # root: rwx, nftadm: r-x, altri: niente
sudo setcap cap_net_admin+ep /usr/local/bin/nftui
```

- La capability viaggia con il **file**, non con l'utente: `chmod 755` +
  `setcap` consegna in pratica il potere di riscrivere il firewall a ogni
  account locale. `chmod 750` con un gruppo dedicato è ciò che lo tiene
  contenuto.
- Un binario `setcap` aggira `sudo`, quindi **non c'è alcuna voce nel
  registro di autenticazione di sudo** e `SUDO_USER` è vuoto — affidati a
  `NFTUI_AUDIT_LOG` per la traccia delle modifiche (cattura comunque l'UID
  e l'utente reali).
- Mantieni il binario e le sue directory superiori scrivibili solo da
  `root`, così il file portatore della capability non può essere sostituito.

### Difesa in profondità

- Attiva il [registro di audit](#registro-di-audit) (`NFTUI_AUDIT_LOG`) così
  ogni mutazione è attribuita e datata — il SO controlla *chi può eseguire*
  nftui; il registro di audit annota *che cosa è cambiato*.
- Usa `--read-only` per ruoli di ispezione / audit che non devono mai mutare
  lo stato.
- `sudo` si integra con **PAM**: ri-autenticazione, MFA o restrizioni di
  orario / host (`pam_time`, `pam_access`) si configurano nello strato PAM —
  questo è l'"involucro PAM" di nftui; lo strumento non aggiunge di
  proposito alcun controllo di accesso proprio.

## Registro di audit

Per la gestione delle modifiche e la conformità (p. es. SOC 2 / PCI-DSS),
nftui può registrare ogni mutazione dell'insieme di regole che applica.
Imposta la variabile d'ambiente `NFTUI_AUDIT_LOG` sul percorso di un file
scrivibile:

```bash
sudo NFTUI_AUDIT_LOG=/var/log/nftui-audit.log ./nftui
```

Quando la variabile è **assente o vuota, l'audit è disattivato** e nftui si
comporta esattamente come prima — nessun I/O su file nel percorso di
mutazione. Quando è impostata, ogni modifica applicata (creare / eliminare /
rinominare tabelle, catene e set; aggiungere / inserire / spostare /
eliminare / modificare regole; aggiungere / eliminare elementi di set;
eliminare / azzerare oggetti con nome; caricamento via `--config`; flush
dell'insieme di regole) accoda un oggetto JSON per riga:

```json
{"time":"2026-06-19T10:30:00.12Z","uid":0,"user":"root","sudo_user":"alice","op":"delete-rule","target":"ipv4 filter input handle 7","result":"ok"}
```

Ogni voce porta il timestamp UTC, l'UID e l'utente effettivi, l'operatore
umano dietro `sudo` (`sudo_user`, da `SUDO_USER`), l'operazione, l'oggetto
destinazione e l'esito (`result` è `ok` o `error`, con un campo `error` in
caso di fallimento — anche i tentativi respinti vengono registrati).
Proprietà:

- **Solo accodamento** — nftui non fa che accodare; non ruota, non tronca né
  rilegge mai il file. Ruotalo con `logrotate` o spedisci le righe a un
  SIEM.
- **0600** — il file viene creato in lettura/scrittura per il solo
  proprietario.
- **Fail-open** — se il percorso non si può aprire, nftui stampa un solo
  avviso e continua senza audit; un percorso di audit rotto non blocca mai
  la gestione del firewall. Assicurati che il percorso sia scrivibile dal
  processo nftui.

## Scorciatoie da tastiera

### Vista principale ad albero (tabelle + catene)

| Tasto | Azione |
|-------|--------|
| `↑` / `k` | selezione in su |
| `↓` / `j` | selezione in giù |
| `Enter` / `→` / `←` | espandi / comprimi |
| `F3` | apri la catena (elenco delle regole) |
| `n` | nuova tabella |
| `c` | nuova catena |
| `e` | modifica la tabella o la catena selezionata |
| `d` | elimina la tabella o la catena selezionata |
| `/` | cerca |
| `r` | ricarica dal kernel |
| `q` / `Esc` / `Ctrl+C` | esci |

### Vista della catena (elenco delle regole)

| Tasto | Azione |
|-------|--------|
| `↑` / `k` | selezione in su |
| `↓` / `j` | selezione in giù |
| `F3` | vedi la regola |
| `F4` | modifica la regola |
| `a` | accoda una regola in fondo |
| `i` | inserisci una regola prima della selezionata |
| `K` (Shift+k) | sposta la regola selezionata in su |
| `J` (Shift+j) | sposta la regola selezionata in giù |
| `d` | elimina la regola |
| `/` | filtra le regole per sottostringa (verdict, parola chiave della condizione, commento) |
| `Esc` | indietro |
| `q` | esci |

Con il filtro attivo, `↑` / `↓` navigano l'elenco filtrato, `Enter` / `F3`
aprono la regola selezionata in visualizzazione, `F4` apre l'editor ed `Esc`
cancella il filtro.

### Editor di regole

| Tasto | Azione |
|-------|--------|
| `F5` / `F6` | scheda precedente / successiva |
| `Tab` / `Shift+Tab` | campo successivo / precedente |
| `F2` | salva (convalida + applica al kernel) |
| `Esc` / `F3` | indietro |
| `q` / `Ctrl+C` | esci |

## Insieme di regole di esempio

`examples/example-nftables-01.conf` è la fixture canonica di test manuale.
Copre tutte le funzionalità documentate sopra ed è verificata con
`nft -c -f` contro il kernel dell'host. Per un punto di partenza realistico
e di buona pratica invece di una vetrina di funzionalità,
`examples/example-host-firewall.conf` è un firewall di host irrobustito
(ingresso negato per impostazione predefinita tranne SSH/HTTP/HTTPS, uscita
libera, inoltro negato). Carica l'uno o l'altro solo esplicitamente e solo
su un sistema in cui sovrascrivere lo stato di nftables è accettabile:

```bash
sudo nft -c -f examples/example-nftables-01.conf       # controllo di sintassi
sudo nft flush ruleset                                 # azzeramento (PERICOLO in produzione)
sudo nft -f examples/example-nftables-01.conf          # applica
```

> `nftui` stesso **non** muta l'insieme di regole in esecuzione all'avvio —
> legge solo lo stato attuale del kernel e scrive le modifiche che l'utente
> effettua esplicitamente.

## Struttura del progetto

```
main.go                        punto d'ingresso del programma
nft/                           nucleo che parla con il kernel
  rule.go                      parser espressione → struttura Rule
  nft_linux.go                 operazioni CRUD netlink (build tag Linux)
  nft_stub.go                  stub no-op per build non-Linux
  expr/                        helper di formattazione per espressione
  nftserializer/               insieme di regole → output leggibile
ui/                            TUI Bubble Tea
  main_window.go               modello di livello più alto (vista ad albero)
  chain_view.go                elenco delle regole
  rule_view.go                 dettaglio della regola (sola lettura)
  rule_edit.go                 editor di regole con FieldEditor a schede
  field_*.go                   un file per FieldEditor
i18n/                          i18n / localizzazione (cataloghi di messaggi incorporati)
  i18n.go                      rilevamento / abbinamento della lingua + il traduttore T()
  locales/                     cataloghi JSON per lingua (en, hu, es, pt-BR, fr, de, it)
examples/example-nftables-01.conf  fixture di test manuale
man/nftui.1                    pagina di manuale (groff/mandoc; vedi «Installazione»)
CHANGELOG.md                   note per versione (formato Keep a Changelog)
```

## Test

```bash
go test ./...                            # test unitari (nessun kernel richiesto)
sudo nft -c -f examples/example-nftables-01.conf   # convalida la fixture
```

### Test di integrazione

I test sotto il build tag `integration` esercitano i percorsi vivi di
lettura **e** scrittura netlink con gli stessi helper usati dalla TUI:
applicare un insieme di regole via `nft -f` e rileggerlo, oltre a creare /
rinominare / eliminare tabelle e catene e aggiungere / inserire / spostare /
eliminare regole, verificando lo stato del kernel riletto dopo ogni passo.
Sono esclusi dal `go test ./...` predefinito e si saltano da soli quando non
girano come root, quindi un semplice `go test` resta portabile.

```bash
sudo -E go test -tags=integration ./nft/ -v
```

Ogni test crea una tabella con nome univoco (con suffisso timestamp, così le
esecuzioni concorrenti e lo stato residuo non collidono) e la smonta in
`t.Cleanup`, anche quando le asserzioni falliscono. Il binario `nft` deve
essere nel PATH; se manca, installalo dal pacchetto `nftables` della tua
distribuzione.

### Integrazione continua

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) esegue gli stessi
controlli a ogni push e pull request verso `main` / `develop`:

- **Build e test unitari** — `gofmt -l`, `go vet ./...` (build tag
  predefiniti e `integration`), `go build ./...` e `go test -race ./...`.
- **Test di integrazione** — installa il pacchetto `nftables` e poi esegue
  `sudo -E go test -tags=integration -v ./nft/` così il banco di prova ha il
  `CAP_NET_ADMIN` che gli serve per applicare un insieme di regole vivo.
  Scrive un profilo di copertura sull'albero `nft` (`-coverpkg=./nft/...`) e
  stampa il totale nel log del job — il percorso netlink vivo è invisibile
  al profilo dei test unitari, quindi è qui che la sua copertura diventa
  osservabile. Gira solo dopo che il job dei test unitari è verde.
- **Scansione delle vulnerabilità** — esegue `govulncheck ./...` contro il
  modulo e la libreria standard Go. Come controllo a sé (parallelo alla
  build), fa fallire l'esecuzione solo quando una vulnerabilità nota è
  raggiungibile dal grafo delle chiamate di nftui.
- **Controllo di build riproducibile** — costruisce i binari di release due
  volte con `goreleaser build --snapshot` e fallisce se i due differiscono,
  verificando che la build `mod_timestamp` / `-trimpath` / senza CGO sia
  riproducibile byte per byte.
- **Build del flake Nix** — su un runner Nix, `nix flake check` +
  `nix build .#default` costruiscono [`flake.nix`](flake.nix) da capo a
  fondo (compilando nftui ed eseguendo la sua suite unitaria nella sandbox),
  così il flake non può rompersi in silenzio. La prima esecuzione deve
  fissare il `vendorHash` di `flake.nix` — arriva come segnaposto e la build
  fallita stampa il valore vero da incollare.

Gli aggiornamenti delle dipendenze e delle GitHub Actions sono automatizzati
con Dependabot (`.github/dependabot.yml`, settimanale), che apre PR man mano
che arrivano release e correzioni di sicurezza a monte.
`github.com/google/nftables` è escluso da quelle PR perché è tenuto di
proposito a uno snapshot fissato.

La versione di Go proviene da `go.mod` via `actions/setup-go@v6` con
`go-version-file: go.mod`, quindi alzare la versione Go del modulo aggiorna
la CI nello stesso commit. Le esecuzioni concorrenti sulla stessa ref
annullano le precedenti in corso (`cancel-in-progress: true`).

## Processo di release

Le release sono guidate da [Goreleaser](https://goreleaser.com/) e da un
workflow attivato dal tag
([`.github/workflows/release.yml`](.github/workflows/release.yml)):

1. Promuovi la sezione `[Unreleased]` di `CHANGELOG.md` a
   `[X.Y.Z] - <data>`.
2. `git tag vX.Y.Z` e `git push --tags`.
3. Il workflow di Release estrae la sezione `[X.Y.Z]` corrispondente da
   `CHANGELOG.md`, poi esegue Goreleaser, che costruisce binari Linux
   `amd64` / `arm64` riproducibili
   (`CGO_ENABLED=0 -trimpath -ldflags='-s -w'`, `mod_timestamp` fissato
   all'ora del commit), impacchetta ciascuno con `LICENSE`, `README.md`,
   `CHANGELOG.md` e `man/nftui.1` in un `tar.gz`, emette anche pacchetti
   `.deb` / `.rpm` / `.apk` / Arch `.pkg.tar.zst` / OpenWrt `.ipk` (nfpm,
   stesso binario), scrive un `checksums.txt` SHA-256 che copre ogni
   artefatto, e pubblica la GitHub Release con le note curate come corpo.
4. La release è irrobustita con attestazione della catena di fornitura:
   `checksums.txt` è firmato con **cosign** (senza chiave — la firma è
   legata all'identità OIDC del workflow via Fulcio/Rekor, nessuna chiave
   privata memorizzata), viene emesso un **SBOM Syft** per archivio, e viene
   registrata un'attestazione di **provenienza di build SLSA** per gli
   archivi, i checksum e il tarball delle dipendenze qui sotto.
5. Un `nftui-<X.Y.Z>-deps.tar.xz` riproducibile (la cache dei moduli Go, da
   `scripts/gen-deps-tarball.sh`) viene caricato per le build offline dai
   sorgenti — soprattutto l'ebuild sorgente di Gentoo, il cui
   `go-module.eclass` vieta l'accesso alla rete in fase di build. Il suo
   contenuto è fissato da `go.sum`, quindi viaggia nell'attestazione di
   provenienza invece che in `checksums.txt` (già firmato).

Verificare una release scaricata:

```bash
# 1. firma sul file dei checksum (cosign senza chiave). Fissa il firmatario al
#    workflow di release di questo repo E all'emittente OIDC di GitHub — un'identità /
#    un emittente jolly ('.*') prova solo che la firma è internamente valida, non che
#    l'abbiamo prodotta *noi*; accetterebbe quindi una firma di qualsiasi identità
#    Fulcio e vanificherebbe lo scopo della verifica senza chiave.
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/aafeher/nftui/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
# 2. l'archivio contro i checksum fidati
sha256sum --check --ignore-missing checksums.txt
# 3. provenienza di build (lega i byte al workflow di release di questo repo)
gh attestation verify nftui_<ver>_linux_amd64.tar.gz --repo <owner>/nftui
```

Per validare la configurazione in locale senza pubblicare:

```bash
goreleaser check                                                  # solo sintassi della config
goreleaser release --snapshot --clean --skip=publish,sign,sbom    # build in dist/
```

`sign` / `sbom` vengono saltati in locale perché richiedono l'identità OIDC
`cosign` del runner di CI e `syft`; l'attestazione di provenienza è
esclusiva del workflow. L'output snapshot (`dist/`) è nel gitignore, quindi
l'albero di lavoro resta pulito.

## Cronologia delle versioni

Le note per versione vivono in [CHANGELOG.md](CHANGELOG.md) nel formato
[Keep a Changelog](https://keepachangelog.com/). Tappe principali finora:

- **v0.1.0** (2026-05-24) — prima release pubblicabile: corrispondenze CT /
  meta / IP / porta complete, tutte le azioni di verdict, CRUD completo
  dell'insieme di regole.
- **v0.2.0** (2026-05-24) — istruzioni NAT (`snat`, `dnat`, `masquerade`),
  `queue`, `quota`.
- **v0.3.0** (2026-05-24) — corrispondenze di protocollo estese
  (ICMP / ICMPv6, SCTP, DCCP, AH, ESP, COMP, Ethernet, VLAN, ARP,
  intestazioni di estensione IPv6).
- **v0.4.0** (2026-05-24) — set, mappe e oggetti con nome.
- **v0.5.0** (2026-05-25) — rifinitura e irrobustimento di set / mappe /
  oggetti con nome (correzione dell'eliminazione dei set a intervalli, flag
  dynset, supporto CIDR, mappe di verdict).
- **v0.6.0** (2026-05-29) — coerenza del canale di feedback e UX dei
  suggerimenti transitori: suggerimenti dell'albero a dissolvenza
  automatica, instradamento unificato degli errori di Reset / Delete.
- **v0.7.0** (2026-05-29) — messaggi d'errore (consiglio `CAP_NET_ADMIN`,
  visualizzazione delle regole respinte) e navigazione (ricerca `/`
  nell'albero, filtro `/` in `chainView`).
- **v0.8.0** (2026-05-30) — opzioni CLI (`--table`, `--config`,
  `--read-only`, `--help`), rifinitura di release (CHANGELOG, pagina di
  manuale), editor `sctp chunk`, caricamento incrementale asincrono.
- **v0.9.0** (2026-06-19) — infrastruttura di release (banco di test di
  integrazione, workflow di CI, elenco di regole virtualizzato, pipeline di
  release Goreleaser, packaging con flake Nix) più un passaggio di
  irrobustimento di livello enterprise: attestazione della catena di
  fornitura (cosign / SBOM / provenienza SLSA), scansione delle
  vulnerabilità in CI, un registro di audit delle mutazioni opzionale,
  convalida degli identificatori come difesa in profondità, e documenti di
  governance e deployment (`SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`).
- **v1.0.0** (2026-06-20) — prima release stabile: percorsi di installazione
  ampliati (Debian / RPM, pacchetti Alpine / Arch / OpenWrt, un'immagine
  Docker, riferimenti comunitari Gentoo / AUR), riproducibilità dimostrata e
  corsie CI per il flake Nix, l'opzione `--version`, un tarball delle
  dipendenze dei moduli Go per build offline, e la resa degli indirizzi IPv6
  di origine / destinazione.
- **v1.1.0** (2026-06-21) — UX di adattamento al terminale e navigazione più
  un'ondata di irrobustimento sicurezza / CI: minimo 80x24 con ritaglio
  della cornice e invito al ridimensionamento, resa su schermo alternativo,
  scorrimento-al-focus nell'editor di regole e scorrimento nella vista della
  regola, intestazione di catena compatta; correzioni per il flush
  dell'insieme di regole all'uscita e la doppia resa delle regole; OpenSSF
  Scorecard / CodeQL / Codecov, obiettivi di fuzzing Go e actions fissate
  per SHA.

- **v1.2.0** (2026-07-18) — internazionalizzazione e localizzazione: tutta la
  TUI è localizzata — la fonte inglese più ungherese, spagnolo, portoghese
  brasiliano, francese, tedesco e italiano — tramite cataloghi di messaggi
  incorporati a parità verificata, selezione via `--lang` / locale POSIX,
  mnemonici di conferma localizzati (l'alias tedesco `j` è condizionato alla
  lingua per proteggere la memoria muscolare dello scorrimento vim), e una
  coppia completa pagina di manuale + README per ogni lingua.
## Licenza

MIT — vedi [LICENSE](LICENSE).
