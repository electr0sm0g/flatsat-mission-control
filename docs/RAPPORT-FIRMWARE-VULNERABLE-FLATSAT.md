# Rapport — Catalogue exhaustif de vulnérabilités à implémenter dans un nouveau firmware FlatSat

**Objet** : concevoir un firmware « vulnerable-by-design » pour le hardware FlatSat v1.0 (Pwnsat / Electronic Cats) couvrant un maximum d'attaques documentées dans le cours *Pentest offensif complet d'un CubeSat selon SPARTA (Space Attack Research and Tactic Analysis, The Aerospace Corporation)*.

**Méthode** : lecture intégrale du dépôt `github.com/Pwnsat/FlatSat` (firmware v1.0.3, 22 fichiers source lus en totalité ; BOM KiCad `FlatSat.csv` ; nétillage PCB vérifié ; scripts d'attaques 00–07 ; README firmware) croisée avec les 12 chapitres du cours final (2120 lignes, ~90 attaques/vulnérabilités extraites). Chaque proposition est jugée sur un critère unique : **réalisable sur le silicier réellement présent sur la carte**, sans ajout de composant.

---

## 1. Périmètre matériel réel (vérifié BOM + PCB)

| Composant | Référence | Rôle firmware | Exploitable offensivement |
|---|---|---|---|
| OBC | Raspberry Pi **RP2040** (U9), dual Cortex-M0+ @133 MHz, 264 Ko SRAM | C&DH | M0+ **sans MPU**, VTOR en RAM, pas de TRNG matériel (ROSC non qualifié), pas d'accélération AES |
| Liaison montante | **SX1262** #0 (U4), LoRa 918 MHz / BW 250 kHz / SF7 / CR 4/5, **CRC désactivée** (`radio0.setCRC(0)`), sync word privé standard 0x12 | RX TC | injection, bit-flips silencieux (pas de CRC), flood, sync word known |
| Liaison descendante | **SX1262** #1 (U4), LoRa 916 MHz | TX TM | écoute, squat de fréquence (le firmware TX sur fréquence arbitraire via `BROADCAST_MSG`) |
| Flash | **IS25LP032D 4 Mo** (U5) sur bus **QSPI** (`/QSPI_SS`,`/QSPI_SCK`,`/QSPI_SD0..3`, vérifié au PCB) | boot XIP | **zone de stockage A/B + persistance actuellement sous-exploitée par le firmware** (le FW v1.0.3 n'utilise que le flash interne 2 Mo via UF2) |
| Capteurs | **BME280** (U11) + **LIS2DH12** (U10) sur I2C (GPIO 20/21) | télémétrie | bus I2C **physiquement exposé sur headers** → esclave malveillant |
| GPS | module externe sur **UART1, GPIO 0/1** (pins `PIN_GPS_TX/RX`), 9600 baud NMEA | nav + **gate d'authentification GS** | injection UART physique ou spoof L1 réel (déjà démontré par `04_gps_spoofing_rf.py`) |
| Console/debug | USB-C (TinyUSB, énumération USB pico stock) ; UART `Serial` 921600 ; **SWD** (J4, DNP) | commande + logs | débogage physique, dump du code (clés en .text) |
| Divers | RGB SK6812, 2 boutons, SMA ×2, fusible 0,75 A | — | — |

**Contraintes structurantes (ce que le hardware n'est PAS)** : pas d'ADCS réel (pas de roues de réaction/magnéto-coupleurs/aimants — seulement un accéléromètre), pas d'EPS réel ( alimentation USB — pas de bus 24 V, pas de chauffages, pas de capteurs de courant par branche), pas de FPGA, pas de HSM/SE, pas de contrôleur CAN (le RP2040 n'en a pas ; sans PHY CAN peuplé, le bus SpaceCAN reste une **simulation logicielle**, ce que le firmware fait déjà), bandes ISM 915 MHz et non UHF 437 / S / X. Tout ce qui touche physique RF pure (Doppler, overshadowing, bilan de liaison, fingerprinting amp_var, MACNN) relève du **plateau SDR de l'attaquant**, pas du firmware — le firmware doit en revanche **exposer les hooks** (RSSI/SNR par TC, mode, horodatage) qui rendent ces attaques mesurables.

---

## 2. Base line : vulnérabilités déjà présentes dans le firmware v1.0.3

À conserver telles quelles (elles font l'objet des attaques publiées 00–07) :

| ID | Vulnérabilité | Localisation | Attaque |
|---|---|---|---|
| V0-01 | Énumération APID non authentifiée (18 APID TC répondent sans garde) | `commandApidHandler` | 00 |
| V0-02 | **AES-128-ECB, clé statique en dur** `"PWNsatLabKey1234"`, sans IV ni rotation, chiffrant TM **et** TC | `secure_link.cpp` | 01 |
| V0-03 | **BROADCAST_MSG : underflow entier** → `memcpy` de SIZE_MAX → crash (pas de watchdog → briquage jusqu'à power-cycle) | `worker.cpp:1791-1798` (`msg_len = payload_total - 2`) | 02 |
| V0-04 | `SET_THRUSTER` sans authentification | APID 0x04 | 03 |
| V0-05 | GPS NMEA **sans vérification de checksum**, sans plausibilité de saut de position | `sensors.cpp` | 04 |
| V0-06 | Auth GS = `response = challenge ^ 0xC0DEFACE` (clé XOR statique), **challenge prédit par seed `millis()∧GPS` sans TRNG**, et **fuite du challenge dans la TM** `GS_ACCESS`/`GS_STATUS` | `worker.cpp` | 05 |
| V0-07 | **Aucun anti-rejeu** : le `sequence_count` SPP reçu est loggué jamais comparé ; header primaire toujours en clair ; secondary header « sécurisé » = compteur echo non vérifié | `commandHandlerInternal`, `spp.cpp` | 06 |
| V0-08 | `RESETC` non authentifié (`watchdog_reboot`) — DoS à volonté, pas de compteur de reboot | APID 0x02 | 07 |
| V0-09 | `FLASH_READ` « déverrouillé » par tag codé en dur (`window_id=0xA5`, `unlock=0xC35A`) + blob secret (`FLAG=PWNSAT{...}`) | `worker.cpp:123-131` | — |
| V0-10 | **Downgrade crypto** : `AES_CONFIG` accepte le toggle **en clair** même lien sécurisé actif (`data_len %16 != 0` → chemin non déchiffré) → n'importe qui éteint le chiffrement | `extractToggleConfigMode` | — |
| V0-11 | Malfaçon ECB active : en-tête primaire SPP **toujours en clair** (APID/seq/length non protégés) + bit-flips ECB contrôlables (C⊕Δ → P⊕Δ) | `worker.cpp`/`secure_link.cpp` | — |
| V0-12 | Backdoor debug USB : `DEBUG_CONFIG` (USB only) **désactive tout le chemin AES** (bypass complet chiffrement/déchiffrement) | `bypass_secure_link` | — |
| V0-13 | SpaceCAN simulé : pas d'authentification d'origine (#23), DoS par flood d'arbitrage, attaque **bus-off** (TEC/REC→256), reassembly fragmenté avec **débordement global 2 octets** (`seq*6 + len ≤ 258 > buffer[256]`, #26) et mélange de `can_id` (#27) | `spacecan.cpp` | — |
| V0-14 | `SET_BEACON_RATE` accepte 0 s → intervalle 0 → **flood permanent de beacons** sur le downlink | `worker.cpp:1523-1529` | — |
| V0-15 | **Pas de watchdog applicatif armé** : tout crash (V0-03) est une perte de mission permanente ; `ledBlink` bloque la boucle jusqu'à 3,2 s (amplificateur de DoS) | `softwareReset`, `led.cpp` | — |
| V0-16 | `spp_unpack_packet` : `length==200` → `memcpy` de 201 octets dans `data[200]` (**off-by-one**) ; aucune vérification `buffer_len ≥ length+7` → **lecture hors limites** jusqu'à 201 o dans le tampon VLA d'uplink | `spp.cpp:152-180` | — |
| V0-17 | Parseur GPS `strtok_r` : les champs vides consécutifs s'effondrent → **désalignement de colonnes** exploitable par phrase NMEA forgée (`$GPRMC,A,,...`) | `gpsSplitLine` | — |
| V0-18 | Fuite d'information par télémétrie : `GS_STATUS` expose lat/lon/rayon/cité de la station (36.1699, −115.1398, 35 km) — géolocalisation de la station sol par simple écoute | `telemetrySPPTransmitGroundStatus` | — |

Catalogue interne du projet : ces V0 couvrent les findings #4, #5, #10, #12–17, #21–22 (+ #23, #26–28 SpaceCAN).

---

## 3. Correspondance cours → faisabilité

Sur les ~90 attaques/vulnérabilités extraites des 12 chapitres :

- **≈ 45 sont directement implémentables** dans le firmware sur ce hardware (nouvelles fonctions à écrire sur silicier existant) — section 4 ;
- **≈ 15 sont du ressort plateau SDR/physique** (Doppler 133 kHz d'accrochage Costas, overshadowing β=13 dB/PIRE kW, fingerprinting PA amp_var, MACNN, IWAT) — le firmware fournit uniquement les hooks (RSSI/SNR/TM mode/timestamp) ;
- **≈ 20 sont côté segment sol ou chaîne de développement** (XSS/CSP unsafe-inline COSMOS, path traversal `/openc3-api/tables/`, Socket.IO 7000, QuestDB, Redis, confusion npm/Verdaccio, conteneurs root) — hors périmètre firmware satellite, documentées dans la matrice comme attaques de la stack compagnon PWNSAT-C3 ;
- **≈ 10 ne sont pas transposables** sans changer le hardware (torque magnétique réelle 5°/s, bus 24 V EPS, SpaceWire/MIL-1553, LEAP sur CAN 500 kbps réel, secure boot FPGA ECDSA P-384 avec RoT gravé) — simulées en modèles d'état si utile, voir 6.

---

## 4. Catalogue des vulnérabilités à implémenter (nouveau firmware « v2 vulnérable »)

Convention : **ID**, tactique SPARTA (codes du cours), source (chapitre du cours), mécanisme, **implémentation concrète sur FlatSat**, CWE, PoC. Tout est écrit en C/C++ Arduino-Pico, 2 cœurs (core 0 = boucle télécom existante, core 1 = modèle de mission).

### 4.A — Reconnaissance (REC)

**V-01 · Fuite d'inventaire CPE par `SEND_FW`** — REC-0001.01 — *Ch.5, Ch.6*
- Version firmware renvoyée en clair (`1.0.0`) sans challenge → l'attaquant identifie la base exacte et le catalogue de CVE associées (équivalent SBOM/public CVE mapping).
- Implémentation : exister (APID 0x03) + y ajouter build id, hash SHA-256 tronqué de l'image, table APID→min-length. Gratuit.
- CWE-200. PoC : `SEND_FW` → comparer à la release GitHub.

**V-02 · Balise d'état trop bavarde (prédiction de fenêtre)** — REC-0001/03, REC-0003.02 — *Ch.5.1*
- Le beacon TM doit exposer (comme AX.25 FUNcube) : mode mission, « tension batterie » (modèle virtuel), timestamp, compteur de passes → l'attaquant déduit l'état de protection (AES on/off, GS mode) et la fenêtre d'injection sans rien casser.
- Implémentation : 8 octets de plus dans le payload beacon `telemetrySPPTransmitBeacon` + bit `SECURE_LINK` déjà calculé par `missionStatusFlags`.
- PoC : écouté RTL-SDR → prédire le moment où GS mode = off.

**V-03 · Exposition RSSI/SNR par TC reçue (oracle Doppler/fingerprint)** — REC-0003 — *Ch.1, Ch.5.2*
- Toute TC reçue génère une TM d'acquittement incluant RSSI + SNR + décalage de fréquence estimé (RadioLib `getFrequencyError()`) → mesure par l'attaquant du seuil d'overshadowing et de sa propre signature (boucle de feedback pour régler sa PIRE), et hook pour un futur IDS RF.
- CWE-200. Coût : 6 o de TM.

**V-04 · Fuite de RAM non initialisée dans le padding TM (canal Heartbleed)** — REC-0001.01 / EX-0009 — *Ch.7.1 (buffer overread ICP ESTCube-1)*
- Les TM courtes sont remplies jusqu'à une taille fixe avec les **octets de RAM tels quels** (au lieu de zéros) → fuite d'adjacents (amorces de challenge, fragments de piles, miettes de clés AES round-key).
- Implémentation : `APID 0x21 PADDING_CONFIG` (mode 0=zéros, 1=RAM crue) — mode 1 par défaut. Le `memset(0,sizeof)` actuel de `spp_unpack` saute déjà sur le chemin `data` ; côté TX, ne plus nettoyer `buffer[MAX_PAYLOAD_CHUNK]`.
- CWE-201. PoC : diff de deux beacons → octets non nuls stables.

**V-05 · Lecture mémoire arbitraire `MEM_READ` (overread à taille attaquante)** — EX-0009.01 — *Ch.2.1 (ESTCube-1 ICP size-field overread)*
- `APID 0x19 MEM_READ offset(u32) len(u16)` : borné à la SRAM (0x20000000–0x20040000) mais **pas** au blob : lit n'importe quelle RAM → extraction de la clé de session, de la table SA, de l'état FDIR (l'équivalent strict du Heartbleed ICP d'ESTCube-1).
- CWE-125. PoC : lire les 16 o de `gs_shared_auth_key` (0xC0DEFACE) puis déchiffrer les GS_ACCESS passés.

### 4.B — Développement de ressources (RD)

**V-06 · Métadonnées de passe dérivables depuis le sol** — RD-0002 — *Ch.1, Ch.7.1*
- Rien de neuf côté firmware : fenêtre 5–15 min, TLE publics, cadence beacon. Le firmware doit juste **respecter une cadence stable** (V-02) pour que l'attaquant pré-programme l'injection. Statut : inhérent, documenté.

### 4.C — Accès initial (IA)

**V-07 · Chaîne de commande sans fraîcheur (rejeu plein)** — IA-0008.01 / EX-0009 — *Ch.3.1, Ch.7.1*
- Compléter V0-07 par une **fenêtre d'acceptation ARC paramétrable** style SDLS : `APID 0x15 SDLS_CONFIG {mode, arc_bits∈{16,20,32}, window∈{1,5,15}}`. Mode par défaut : **16 bits, W=5, et réinitialisation de l'ARC au boot** (compteur en SRAM — comme CryptoLib, clés/compteurs volatils).
- Conséquences mesurables exactly as in course : à 2 trames/s, bouclage en 32 768 s ≈ 9,1 h ; P(acceptation)=W/2^arc_bits=7,63·10⁻⁵ ; 64,2 bouclages/3 ans → ~321 trames jouées ; **rejeu massif post-reset** (le compteur repart de 0 → toute capture d'avant-reboot est rejouable).
- CWE-294. PoC : `06_replay` étendu + RESETC + re-rejeu.

**V-08 · SDLS simulé avec table SA 64 entrées dont 43 en mode Clear** — IA-0008 / EX-0006 — *Ch.2.1, Ch.3.1*
- `sa[64]` avec `est`/`ast` initialisés à 0 → **43 SA « SA_PLAINTEXT »** ; un TC avec SPI=44 (0x002C) passe **sans MAC, sans ARC** ; l'attaquant omet même le security header (trame CCSDS standard acceptée).
- Implémentation : header sécurité optionnel `[SPI(2)|ARC(4)|MAC(16)]` dans les TC, vérifié si `sa[spi].ast!=0`. Layout mémoire volontaire : après `sa[64]`, tampons zéro (reproduit le comportement CryptoLib).
- CWE-862. PoC : trame sans MAC avec SPI=44 exécutée.

**V-09 · SPI non borné → lecture hors limites (CVE-2024-44911/44910/44912 reproduites)** — EX-0009.01 — *Ch.3.2*
- `get_sa_from_spi(spi)` retourne `&sa[spi]` sans `spi<64` : SPI=8327 (0x2081) tombe dans la zone adjacente initialisée à zéro → mode Clear + `CRYPTO_LIB_SUCCESS` ; d'autres SPI ≥ 8192 touchent une zone non mappée → **HardFault → DoS** (le RP2040 n'a pas de MPU : la faute dépend du mappage réel SRAM — reproduire en plaçant la table près de la fin d'une section).
- Fuzzing : balayage SPI 64→65 534 (SPACE-SAT-style) faisable en < 1 passe (26 667 slots TC/8 min à 9,6 kbps equivalent LoRa SF7 ≈ débit utile ~11 kbps : ~2 700 trames/min → ~25 min — faisable sur 4 passes, à noter dans la doc attaquants).
- PoC : `SDLS_OTA` + SPI=8327.

**V-10 · OTAR acceptant une master key nulle non configurée (expropriation d'opérateur)** — EX-0009.01 — *Ch.7.2*
- Table de 128 master keys initialisées à zéro au boot, seule la condition `m < 128` est testée (ni `state`, ni `len`). L'attaquant poste une OTAR (`APID 0x16`) chiffrée avec K[64]=0²⁵⁶ → installe **sa** clé de session sur n'importe quelle SA → les TC de l'opérateur légitime sont ensuite **rejetées (MAC invalide)** → expropriation totale jusqu'au RESETC.
- Budget fidèle au cours : ~64 trames ≈ quelques secondes de passe ; réversibilité par reset ; l'OTA/OTAR n'utilise **pas** l'ARC (répétable sans limite).
- AES-128-CTR/CMAC additionnels sur notre AES logiciel (`secure_link.cpp` fournit le bloc ; CTR trivial, CMAC = sous-clé K1⊕Rn).
- CWE-321/CWE-1188. PoC : OTAR×64 → STATUS de l'opérateur rejeté → RESETC → OK.

**V-11 · Oracle de vérification de clé (IV réutilisé → 16 octets de clair)** — Collection/IA — *Ch.7.2*
- `APID 0x17 KEY_VERIFY key_id` : le firmware chiffre un défi 16 o avec l'**IV de la TC + 1** ; en rejouant la même TC (V-07, pas d'ARC sur Key Verification) l'attaquant obtient E₁=E(IV+1) pour deux clairs différents → `M₁ ⊕ M₂ = C₁ ⊕ C₂` → récupère 16 o de clair d'un échange dont il ne connaît pas la clé. Codé « en dur sur la clé 0 » comme CryptoLib.
- PoC : 2 requêtes même IV → XOR.

**V-12 · Bit-flips silencieux sur la TC (CRC radio désactivée + absence d'intégrité payload)** — EX-0009 / IA-0008 — *Ch.1.1, Ch.2.1*
- Déjà factuel (V0-11 + `setCRC(0)` uplink) : le flip d'un bit de ciphertext ECB flip le même bit de clair → sans connaître la clé, l'attaquant retourne `SET_THRUSTER power 0x10→0x30`, change un APID (header clair), un `length`, ou le flag SecHdr. Le récepteur ne **voit rien** (pas de CRC, pas de MAC).
- À rendre mesurable : compteur TM « TC acceptées avec CRC radio KO » — toujours 0 car CRC désactivée ; une config `RADIO_CRC` (off par défaut) donne à l'attaquant un levier de détection/avoidance.
- CWE-354. PoC : ±1 bit sur 8 rejeux de STATUS → réponses valides modifiées.

**V-13 · Buffer overflow « nom de log » (strcat OPS-SAT ADCS) — corruption globale déterministe** — EX-0009.01 — *Ch.2.2*
- `APID 0x1A SET_LOG_NAME` : `strcpy` d'une chaîne TC dans un buffer statique `char log_name[32]` suivi de variables d'état **choisies par le layout** (ex. `mission_ctx.usbDebugEnabled`, puis `secure_link_enabled`) → une TC unique de 33–48 o flippe un flag critique (equivalent de la RCE par une seule TC d'OPS-SAT ; ici corruption d'état, pas de détour de Pc car M0+ sans canary ni MPU — c'est déjà ce que fit ESTCube/OPS-SAT sur leurs cibles).
- CWE-120. PoC : nom de 40 'A' → `AES_CONFIG` bascule tout seul, visible en TM STATUS.

**V-14 · Primitive `MEMCPY` en TC (source/dest/taille fournies par la TC) → RCE RP2040** — EX-0009.01 — *Ch.2.1 (Flying Laptop), Ch.7.1 (ESTCube-1 TC memcpy)*
- `APID 0x18 MEMCPY src(u32) dst(u32) len(u16)` borné SRAM. Avec V-05 (lecture) + V-14 (écriture), la chaîne complète : **réécrire `SCB->VTOR` (0xE000ED08, registre en PPB accessible)** — ou la table des vectifs copiée en RAM (le SDK copie déjà l'image d'interruptions en RAM) — puis déclencher l'IRQ → **exécution de code arbitraire réelle** sur RP2040 (le M0+ a son VTOR en RAM, aucun moyen de le verrouiller). C'est la RCE la plus spectaculaire obtainable sur ce board, l'équivalent direct des `TC memcpy` de Flying Laptop/ESTCube.
- Variantes d'écriture ciblant les périphériques : GPIO0/1 (tuer le GPS), registers PWM LED, `watchdog->scratch` (persistance d'un cookie entre reboots).
- CWE-787. PoC : shellcode Thumb-2 40 o dans la RAM d'un tampon, VTOR→shellcode, IRQ.

**V-15 · Flood d'uplink → perte de télémétrie (DoS sans crash)** — Impact/IA — *Ch.1, Ch.4.3 (analogie Socket.IO)*
- Le handler traite chaque TC avec `ledBlink` (bloque 1,6–3,2 s par erreur !) + `printHexDump` : ~30 trames malformées = 30× blink = **le beacon et les passes TM sont gelés** plusieurs minutes → perte de fenêtre complète, sans redondance de réception.
- Implémentation : conserver tel quel (bug fonctionnel = vulnérabilité) + exposer le compteur TM « loop stalls ».
- PoC : flood 0xFF×32.

### 4.D — Exécution (EX)

**V-16 · Exécution de commandes sous privilèges induits (analogie root-CAN OPS-SAT)** — LM-0002/EX-0009.02 — *Ch.8.1*
- Le pont radio→SpaceCAN n'existe pas (la console SpaceCAN est USB-only). L'ajouter : `APID 0x1C SC_INJECT can_id(u32) dlc data[]` **accessible par radio**, sans authentification d'origine → toute TC radio valide = « processus root sur le bus » (exactement la démo Thales CYSAT : UID≠0 → trame → exécution root). Effets réels : puissance des thrusters virtuels, charge batterie simulée, arrêt bus-off de nœud.
- CWE-250.

**V-17 · Micro software-bus pub/sub interne avec MID forgeables (cFS SB)** — EX-0014.03 / LM — *Ch.8.2*
- Nouveau module `sb.cpp` : routage interne par **Message ID uniquement**, sans identité d'émetteur. APID `0x1B SB_PUBLISH mid data` : n'importe qui (radio incluse) publie une trame « quaternion » ou « raw sensor » MID 0x101 → l'ADCS virtuel (4.I) et le FDIR consomment ces valeurs comme authentiques → **désactivation du « capteur » légitime** en publiant un ENABLE/DISABLE, télémétrie falsifiée byte-identique.
- Option défense : mode `SB_AUTH` (tag 4 o) désactivé par défaut → montre le compromis.
- CWE-287.

**V-18 · Image OTA non signée + slots A/B dans la flash QSPI 4 Mo (rollback)** — IA-0001.02/IA-0006 — *Ch.6.2, Ch.6.3*
- La flash QSPI de 4 Mo (au-delà de l'image courante ~1,2 Mo max UF2) : découper 2 slots de 1,5 Mo + 1 secteur de métadonnées. Nouveaux APID `0x1F OTA_PUSH` (chunk 64 o, CRC-16 par chunk, **pas de signature par défaut**) + `OTA_ACTIVATE` (écrit le magic de boot dans le secteur méta). Un watchdog de confirmation (30 s sans ACK) revient au slot A.
- Vulnérabilités livrées : (a) image arbitraire par simple écoute/injection TC → exécution au boot suivant (STORK-1 multi-tenant) ; (b) **rollback** : réactivation d'un slot antérieur valide — le compteur anti-rollback monotone existe (`ARWC` dans le secteur méta) mais est **désactivé par défaut**, exactement le trou des manifests SUIT sans counter (Ch.6.3) ; (c) pas de test `state`/`len` des clés : la clé ed25519 de vérification optionnelle est « pré-enregistrée » en flash lisible (equivalent SPR-221 readout, clé partagée constellation SPR-220).
- Implémentation signature : vérif ed25519 logicielle (ou HMAC statique si budget) ≈ 100–300 ms au boot — chiffrable, mesurable : donne un chiffre de surcoût « sur STM32F405, +3 848 o RAM / +19 328 o flash » équivalent pour RP2040.
- CWE-345/CWE-434.

### 4.E — Persistance (PER)

**V-19 · File de tâches planifiées persistée en flash, rejouée au boot** — PER-0002 — *sujet : « persistance via FDIR et tâches planifiées »*
- `APID 0x1E SCHED_ADD {tick(u32)|every(u16), apid, len, payload}` stockée dans le secteur config flash (les fonctions ROM `rom_flash_range_*` écrivent la flash XIP sans risque — pattern officiel Pico). Au boot, le firmware **rejoue les tâches sans vérifier leur origine** → une TC de l'attaquant survit au RESETC (la « réversibilité par reset » de V-10 est cassée — c'est le correctif que l'attaquant doit poser). Limite : 16 entrées, effacement par `SCHED_CLR`… que l'attaquant peut protéger en désactivant le poll (voir V-21).
- Équivalent strict : tâches planifiées + FDIR (CM0044 inversé).
- CWE-269.

**V-20 · Dictionnaire de contingence FDIR modifiable (l'analogue embarqué du `executable.jar`)** — PER-0002.02 Backdoor:Software — *Ch.9.2*
- Le FDIR (V-24) exécute au déclenchement safe-mode une **liste de TC « de secours »** stockée en flash, **sans hash d'intégrité au chargement** (le superviseur Java « writable by root, démarré tôt, quasi toujours actif » devient la séquence FDIR « démarrée tôt, toujours active »). L'attaquant remplace une entrée (ex. `DETUMBLE`) par `SET_THRUSTER 0 255` → à chaque événement FDIR futur, sa commande s'exécute : persistance + defense evasion (indiscernable d'une maintenance).
- Correctif documentable : `FDIR_HASH_SET` qui grave le SHA-256 de la table dans un secteur OTP-like (effaçable une seule fois — comme le hash jar en OTP du cours, et le même défaut « chaque OTA réécrit l'ancre »).
- CWE-427.

**V-21 · Cookie de persistance dans les registres watchdog (scratch RP2040)** — PER — *technique RP2040*
- Les 8 registres `watchdog->scratch[]` **survivent au watchdog reboot** : l'exploit V-14 y écrit un cookie ; au boot, si cookie==magie, le firmware désarme le GS mode / réactive la file V-19. L'opérateur ne peut le nettoyer que par power-cycle (débrancher l'USB) — en orbite : brownout. Illustre pourquoi « reset ≠ clean slate ».
- CWE-326.

### 4.F — Évasion de défense (DEF)

**V-22 · Downgrade de protection par forçage safe-mode (SV-CF-4 embarqué)** — EX-0006 / EX-0011 / REC-0007 — *Ch.9.1*
- Le safe-mode (déclenchable à distance : quaternions faux via V-17, « tilt » via thrusters, GPS perdu, batterie V-25) applique une table de relâchement **exactement les 6 vecteurs EX-0006 du cours** :
  1. flags maintenance/test acceptés (`TESTMODE` APID),
  2. fallback null-cipher (`AES_CONFIG` off, déjà V0-10),
  3. dégradation de suite (mode ECB forcé si une mode CCM avait été activée),
  4. **ARC reset + fenêtre élargie W=15** en contingence,
  5. dictionnaire de contingence exécuté (V-20),
  6. chemin clair non chiffré (le GS gate se ferme mais `GS_ACCESS`+`DEBUG` restent ouverts → l'analogue du « mode Clear toujours joignable » CryptoLib).
- La TM beacon **n'est pas cloaked** (CM0006 non implémentée par défaut) : le bit safe-mode est visible dans les 8 o de beacon → l'attaquant *détecte* la fenêtre (REC-0007) puis l'exploite dans les <2 min du cours.
- PoC bout-en-bout : injection quaternion → safe → commande sale → exit safe.

**V-23 · Absence de journalisation des TC (pas d'attribution ≤3 min)** — DEF — *Ch.7.1 (SV-IT-2 : attribution ≤3 min), Ch.9.2 (P_detect=0)*
- Pas de log persistant par défaut (le secteur flash de log existe mais est **off** par défaut, et le `Serial` efface tout au reboot) → post-mortem impossible hors fenêtre. Option `LOG_ENABLE` (1 secteur, circulaire, horodaté millis) montre le coût d'acquisition et permet l'attaque « log flood → eviction » (le log circulaire écrase la preuve en < 40 min de flood).
- CWE-778.

**V-24 · Détecteur d'anomalies EWMA contournable (le LSTM appauvri du cours)** — DEF / détection — *Ch.12.2*
- Modèle : EWMA sur 4 canaux (tilt virtuel, courant moyen, tension moyenne, cadence TC) avec seuil z∈[2,5;10]. Implémentation : 200 lignes, 1 multiply/échantillon, ~10 µs.
- Faiblesse mesurable fidèle au cours : une dérive **≤ 5 %/passe** reste sous le résidu lissé (P(évasion)≈0,31/passe annoncé sur les anomalies contextuelles) → l'attaquant qui monte la puissance des thrusters de 4 % par passe n'est jamais signalé ; les anomalies « contextuelles » (V-17 publie des MID valides sémantiquement faux) ne lèvent rien.
- Sortie : bit FLAG_ANOMALY dans STATUS + trame ALARM. Le contournement se prouve en logs.
- (Un vrai LSTM 2×80 est jouable sur M0+ à 1 kHz mais inutile : la vulnérabilité visée est le seuillage, pas le modèle.)

### 4.G — Mouvement latéral (LM)

**V-25 · SpaceCAN par radio : bus non authentifié complet** — LM-0002 (TID-114/TID-412) — *Ch.8.1*
- V-16 branché + conservations existantes #23/#26/#27/#28 : injection d'origine, flood d'arbitrage (req 0x280 affame rep 0x300), **bus-off ciblé** (32 trames malformées → TEC 256 → nœud MOTOR/BATTERY déconnecté silencieusement → effet physique virtuel : le thruster ne répond plus, `SC RESET` requis), reassembly overflow (2 o au-delà de `ctx->buffer[256]` corrompent `last_update_ms` du contexte → DoS de réassemblage).
- Tout est déjà simulé en console USB ; le rendre radio-accessible est le seul travail, et c'est la faille LM la plus fidèle au cours.

**V-26 · Pont radio→I2C : injection capteur par bus physique exposé** — LM/Collection — *Ch.8 (bus internes sans authentification), Ch.8.2*
- Le header J3 casse le bus I2C hors carte ; un FT232H + MCP23017 font un « esclave BME280 fantôme » : l'attaquant qui accède physiquement au bus (satellite sur banc ou au sol, FlatSat = banc) publie température/pression sur l'adresse 0x77 (le firmware ne scanne qu'0x76 → le clone doit usurper 0x76 en dépit du vrai composant : bus-off du vrai capteur par clock stretching).
- Côté firmware : aucune vérification d'identité du device (le « whoami » du registre CHIP_ID n'est testé qu'au boot, pas périodiquement) → `MISSION_FLAG_BME_OK` reste vrai avec un faux capteur. Flag optionnel `I2C_WHOAMI_PERIODIC` (défaut off) pour chiffrer le compromis.
- CWE-297.

**V-27 · FDIR consommant les MID → latéralisation vers l'ADCS virtuel** — LM — *Ch.8.1/8.2 (chaîne supervision → CAN → ADCS)*
- Combinaison V-17+V-28 : la TC « camera capture » existe (V-31) mais les MID de commande d'attitude sont atteignables par n'importe quel abonné → un implant interne (éventuellement post-OTA V-18) peut commander l'ADCS sans repasser par la radio.

### 4.H — Collecte (COL)

**V-28 · Vol de la session GS par oracle de challenge + clé XOR en dur** — COL — *Ch.7.2, attaques 05*
- Existant V0-06, complété : challenge = seed sans ROSC ; ajouter le mode « challenge dérivé horodaté » (`CHALLENGE_MODE=2`) où l'attaquant qui connaît ±20 s de `millis` (timestamp beacon V-02 !) **précalcule** le challenge → bypass sans même écouter le handshake.
- PoC : offline predict → GS_ACCESS phase 1+2 → gate ouvert 5 min (session 300 s du code actuel).

**V-29 · Échantillon RF par TC pour fingerprinting passif** — COL/REC — *Ch.5.2/5.3*
- Hook de V-03 inversé : le firmware **pe** stocker une fenêtre de 64 IQ-ish (échantillons RSSI+freq error+SNR des 64 dernières TC) exportable (`APID 0x20 TC_STATS`) → l'attaquant peut s'auto-mesurer ; et un défenseur peut y entraîner un détecteur LR (le TinyML du cours : LR 69,5 µs / 0,940 acc — trivial à estimer sur M0+).

### 4.I — Exfiltration (EXF)

**V-30 · Canal stéganographique dans le padding TM (5 bits–10 % du débit)** — EXF/Hidden Channel — *Ch.10.2*
- TM à longueur fixe (128 o) ; `PADDING_CONFIG mode=2` remplit le padding avec les octets d'une **file « covert queue »** alimentée par `APID 0x22 COVERT_ENQ` (queue FIFO 1 Ko) ou par la RAM crue (V-04). Débit mesurable : à SF7/250 k (≈ 11 kbit/s utile), 10 % α ≈ 1 kbit/s ≈ 60 o/passe — l'échelle du cours (732 KiB/passe en S-band 100 kbit/s) re-calibrée pour LoRa, documentée.
- Les compteurs de frames restent cohérents (l'audit COSMOS-like ne voit que du housekeeping valide).
- PoC : 40 o/passe « images » → reconstitution côté sol.

**V-31 · Capture payload non autorisée + audit par compteur VCC contournable** — EXF/EX-0007.02 — *Ch.10.1*
- Le « payload » de FlatSat = la file covert + un mode « snap » (horodatage+lecture instantanée capteurs packée en 32 o « pseudo-image »), `APID 0x23 PAYLOAD_SNAP` → exfiltration par le downlink légitime. Le compteur VCC (= `payloadForwardCount` existant) **est incrémenté** → audit possible ; le mode `VCC_FREEZE` (bit debug, défaut off en GS mode) le gèle → démontre « le compteur d'audit est dans le périmètre de l'attaquant qui a l'écriture mémoire (V-14) ».
- Delta d'audit du cours : +N/N_cap = 33,3 % pour N_cap=3 → reproduction triviale.

**V-32 · Squat de fréquence downlink par l'attaquant (radio squatting)** — EXF — *Ch.2.2 (services UHF additionnels), attaques 03*
- `BROADCAST_MSG freq(u16)` fait déjà émettre le TX **sur la fréquence de la TC** (916→arbitraire MHz, `downlinkRadioTransmitBroadcast`) : un utilisateur malveillant du protocole « relocate » le downlink à sa convenance (squat), le rendant injoignable pour la station légitime, sans aucune authentification de la fréquence. Un simple bornage à une allowlist de 8 fréquences (mode `FREQ_LOCK`, off par défaut) documente la défense.
- CWE-284.

### 4.J — Impact (IMP)

**V-33 · ADCS virtuel : détumble/dérive par thrusters + seuil 5°/s mesurable** — IMP (SV-MA-2/3) — *Ch.11.1*
- Modèle d'état core 1 : attitude (Euler+vélocité) intégrée ; `SET_THRUSTER` = couple (saturation > m_max contourne le B-dot simulé, exactement le mécanisme du cours) ; le **vrai accéléromètre LIS2DH12** mesure la secousse physique quand l'utilisateur fait bouger la carte (démo tangible) et l'état intégré est publié en TM quaternion + tilt °/s. Tumble > 5°/s → FDIR V-22 (détectable par l'attaquant via V-02 comme le cours).
- Dérive orbitale : intégration « Δv » en TM indices (a(e) dérive affichée).

**V-34 · Power drain : chauffe-virtuels + modèle batterie → brownout <24 V** — IMP (SV-MA-8 Power Drain) — *Ch.11.2*
- `APID 0x24 HEATER {id,on}` + compteur d'énergie : `V_batt(t) = f(ΣP·dt, charge)` avec cycle éclipse simulé (35–40 min/95 min) ; sous le seuil 24 V (16,8 V équivalent lipo simulé) → brownout = **faux RESETC global** (purge SRAM → SA/ARC/challenge remis à zéro → l'attaquant rejoue ses captures d'avant-brownout : lien direct avec V-07 et la volatilité CryptoLib).
- L'absence de mesure de courant par branche = le trou EPS du cours (pas d'I-meas → pas de détection).
- Le spam `HEATER` (une TC = 8 o) à 2 trames/s consomme la « batterie » en heures — démontrable en démo accélérée.

**V-35 · Déni de mission par flood beacon/broadcast (l'analogue du `service_control` non authentifié)** — IMP — *Ch.4.3*
- V0-14 (`SET_BEACON_RATE 0`) + V-15 + V0-03 (crash sans watchdog) = trois niveaux de DoS, tous non authentifiés hors GS mode ; et **GS mode est lui-même coupé** par GPS spoof (V-36) ou `GS_MODE 0` depuis USB debug. Les 432 000 o de TM perdus/passe du cours deviennent sur FlatSat : 0 TM pendant N passes, compteur TM figé.

**V-36 · Spoofing GPS → contournement complet du gate GS (chaînage initial access)** — IA-0008 / IMP — *Ch.7 (ESTCube ICP) + attaques 04/05*
- Existant (NMEA sans checksum + pas de plausibilité), renforcé : le firmware doit **démontrer l'enchaînement** spoof→range→auth→TC. Ajouts : (a) refus d'un saut > 500 km/s·Δt si `GPS_PLAUSIBLE=on` (défaut off — la défense chiffrable) ; (b) cohérence temps : l'heure GPS est comparée au delta millis (dérive) → une horloge gelée = anomaly V-24 (option).
- Le GPS est attaqué **au physique** (L1 HackRF — déjà prouvé sur le vrai u-blox ; ou UART J3) : le firmware n'a rien à changer d'autre, mais l'absence de toute vérification au parsing est la décision de conception vulnérable.

### 4.K — Chaîne de développement / supply chain (documenté côté firmware)

**V-37 · Métadonnées de build exposant la base logicielle** — CM0013 — *Ch.6.1*
- La string de version + le banner « PWNSAT DEFCON EDITION » + USB product « Pwnsat - Flatsat » (VID:PID **239A:CAFE**) pointent vers le dépôt public → l'attaquant maps le firmware exact et ses findings. Action : rendre la build-id **reproductible et hachée**, et ajouter un champ `HW/SW ID` renvoyé par `SEND_FW` avec un « manifeste » signable (le manifeste SUIT élagué : 48 o magic+version+counter+sig, signature off par défaut) → supporte la démo rollback V-18.

**V-38 · Compteur anti-rollback en flash effaçable (SPR-215 inversé)** — CM/Supply — *Ch.6.3*
- Le secteur méta du dual-slot est ré-écrivable par TC `ARWC_SET` **sans autorisation** → l'attaquant qui a le gate GS (ou le debug USB) décrémentne le compteur et rollback. Version dure : une seule OTP par sector (l'efface une fois) = défense documentée avec son défaut (OTA = usure d'ancre).

### 4.L — Défenses optionnelles à livrer avec le firmware (pour que chaque attaque ait son contre-mesure mesurable)

| Défense (source cours) | Implémentation FlatSat | Coût mesuré attendu |
|---|---|---|
| SDLS complet (AES-GCM/CMAC + ARC32 + SPI borné) | `SDLS_MODE=1` : +22 o/trame, MAC CMAC ≈ 17 AES → µJ/order of magnitude du cours MSP430 (à mesurer sur M0+ ≈ 30–60 µs MAC) | latence par TC, RAM tables SA |
| CRC LoRa uplink ON | `RADIO_CRC=1` | +1 bit de overhead, détection bit-flips |
| Chiffrement d'horodatage TC (freshness) | challenge 4 o aléatoire ROSC **avec** health-test (1 o de entropy) + HMAC | ROSC biaisé : mesurable |
| Safe-mode cloak (CM0006) | beacon ne publie plus safe-mode en `CLOAK=1` | coût : perte audit sol |
| I2C periodic WHOAMI | 5 ms/cycle/bus | + énergie negligible |
| ed25519 OTA verify | ~200 ms boot | +3,8 Ko RAM / +19 Ko flash, ordres du cours STM32 |
| Watchdog armé + boot counter (scratch) | IWDG 2 s, compteur en `watchdog->scratch` | +reset storms visibles |

---

## 5. Matrice de synthèse — couverture par tactique

| Tactique SPARTA | Vulnérabilités FlatSat electr0sm0g (nouveau firmware) | Attestation (script d'attaque) |
|---|---|---|
| Reconnaissance | V0-01, V-01…V-05 | écoute RTL-SDR + MEM_READ |
| Resource Development | V-06 (inhérent) | plateau SDR |
| Initial Access | V-07…V-15, V-28, V-36 | 00/03/04/05/06/07 + SPACE-SAT-style SPI sweep + OTAR×64 |
| Exécution | V-14 (RCE), V-16, V-17, V-18 | VTOR shellcode demo |
| Persistance | V-19, V-20, V-21 | survie RESETC, cookie boot |
| Defense Evasion | V-22, V-23, V-24 | safe-mode injection + EWMA bypass 4 %/passe |
| Lateral Movement | V-16, V-25, V-26, V-27 | radio→CAN, I2C ghost sensor |
| Collection | V-05, V-28, V-29 | RAM leak, challenge predict |
| Exfiltration | V-04, V-30, V-31, V-32 | covert queue 60 o/passe |
| Impact | V-33, V-34, V-35 (+V0-03/08/14) | tumble 5°/s, brownout 24 V, no-TM ×N passes |

**Taux de couverture** : sur l'inventaire des ~90 attaques/vulnérabilités du cours, ce catalogue en adresse **~60 en firmware ou en hooks firmware** (les V-xx + les V0-xx préservées), ~15 en plateau SDR documentées avec hooks (V-03/V-29), et ~15 explicitement hors hardware (section 6) — soit **≈ 83 % de la matière du cours rendue jouable physiquement** sur une carte à ~60 USD.

### Table des APID proposés (extension du registre mission.h existant)

```
0x01–0x13  conservés (compat 00–07 + PWNSAT-C3)
0x14 GPS_OVERRIDE (debug)      0x15 SDLS_CONFIG
0x16 SDLS_OTA(OTAR)            0x17 KEY_VERIFY
0x18 MEMCPY                    0x19 MEM_READ
0x1A SET_LOG_NAME              0x1B SB_PUBLISH
0x1C SC_INJECT                 0x1D FDIR_CONFIG
0x1E SCHED_*                   0x1F OTA_*
0x20 TC_STATS                  0x21 PADDING_CONFIG
0x22 COVERT_ENQ                0x23 PAYLOAD_SNAP
0x24 HEATER                    0x25 DEFENSES_CONFIG (flags des 4.L)
```

---

## 6. Ce qui n'est PAS implémentable sur ce hardware (honnêteté matérielle)

| Attaque du cours | Why it can't run on FlatSat | Alternative la plus proche |
|---|---|---|
| Overshadowing aval (β, PIRE kW, FUNcube) | physique RF pure, récepteur satellite réel | marge mesurable via V-03 |
| Doppler ±9 kHz / Costas 133 kHz | LEO 437 MHz ≠ LoRa ISM 916 à banc posé | V-03 (freq error SX1262) |
| Fingerprinting amp_var/MACNN | capture large bande + CNN, pas d'accélérateur | V-29 hook LR TinyML |
| Torque magnéto-coupleurs réel 3,9 s→5°/s | pas d'ADCS ni d'aimants | modèle V-33 + LIS2DH12 |
| EPS 24 V, chauffages, gel propergol | alim USB, pas d'EPS | modèle V-34 |
| LEAP 1,998 ms sur CAN 500 k | RP2040 sans CAN + pas de PHY | timing simulé en SpaceCAN v2 (`SC LEAP`, latence injectée) |
| SDLS sur trame CCSDS 232.0 complète (FARM/COP/CLCW) | le FlatSat parle SPP par CSP-like, pas TC-space full FOP-1 | V-07/V-08 au niveau SPP/payload |
| SpaceWire / MIL-STD-1553 / cFS/F Prime | stack temps réel complète hors scale | micro-SB V-17 |
| Secure boot ECDSA P-384 + RoT FPGA | pas de RoT : le RP2040 BootROM ne vérifie **aucune** signature (faille structurelle réelle, documentable) | V-18 éd25519 logiciel = « secure boot mou » |
| COSMOS XSS/traversal/Redis/QuestDB, npm confusion | segment sol/chaîne dev | stack PWNSAT-C3 compagnon |
| OTAR multi-SA sur CryptoLib 64 SA AES-GCM | AES-GCM = 2× le coût ; CMAC+CTR suffisent pédagogiquement | V-09/V-10/V-11 |
| Flash de vol NOR séparée + cold-boot SRAM | pas de SRAM amovible, pas de cold boot | — |

---

## 7. Ordre d'implémentation proposé (4 jalons, ~5 000 LoC, budget mesuré : RAM actuelle 8,4 %, flash 7,8 % de l'image UF2 → 264 Ko/4 Mo largement suffisants)

1. **Jalon 1 — Socle crypto & fraîcheur** (V-07, V-08, V-09, V-10, V-11, V-12, `sbcrc`) : `sdls_sim.cpp` (table SA, ARC, CMAC/CTR sur le bloc AES existant), APID 0x15–0x17. *Rend jouables les chapitres 3 et 7.2 en entier.*
2. **Jalon 2 — Mémoire & RCE** (V-04, V-05, V-13, V-14, V-15, off-by-one V0-16 préservé comme case de fuzzing) : `memserv.cpp` + tests VTOR. *Chapitres 2.1/2.2/7.1 en démonstration physique.*
3. **Jalon 3 — Mission & latéralisation** (modèle ADCS/EPS V-33/V-34, FDIR V-22 + dictionnaire V-20, SB V-17, SpaceCAN-radio V-25/V-16, I2C V-26, GPS V-36 renforcé) : `mission_model.cpp`, `sb.cpp`, `fdir.cpp`. *Chapitres 8, 9.1, 11.*
4. **Jalon 4 — Persistance, exfiltration, défenses chiffrées** (V-18/19/21, V-30/31/32, V-23/24, table 4.L, `DEFENSES_CONFIG`) : `flashstore.cpp`, `covert.cpp`, `anomaly.cpp`. *Chapitres 4 (côté démonstration), 5, 6, 10, 12.*

Chaque jalon livre les scripts d'attaque Python correspondants (réutilisant `lib/pwnsat_packets.py` + variante `_usb.py`) et une fiche de mesure des compromis (µJ/TC, µs/MAC, o de surcharge, secondes de passe consommées) dans l'esprit « compromis mesurés » du cours.

---

## 8. Références

- Dépôt analysé : `Pwnsat/FlatSat@main` (firmware v1.0.3 — `worker.cpp` 1707 l., `secure_link.cpp` 339 l., `spp.{h,cpp}`, `spacecan.cpp` 568 l., `sensors.cpp` 471 l., `ruplink.cpp`, `rdownlink.cpp`, `usbCDC.cpp`, `mission.h`, `pins.h`, `platformio.ini` ; BOM `Hardware/flat-sat/FlatSat.csv` ; nets U5 vérifiés dans `FlatSat.kicad_pcb`).
- Cours source : 12 chapitres + fiches SV-SP-* des vulnérabilités couvertes.
- Référentiels cités par le cours et reproductibles ici : CVE-2024-44910/-44911/-44912 (CryptoLib), ESTCube-1 ICP (Didelot et al.), OPS-SAT (CYSAT 2023 / TID-xxx), Flying Laptop (TC memcpy), CCSDS 355.0B-2 SDLS, SPARTA — Space Attack Research and Tactic Analysis, The Aerospace Corporation (REC/IA/EX/PER/DEF/LM/COL/EXF/IMP + SV-MA/SV-SP/SV-IT/SV-AC).
