# NCSC-archief

Archief van de openbare beveiligingsadviezen van het Nationaal Cyber Security Centrum (NCSC-NL),
in één compact bestand. Het archief wordt gebruikt door de webpagina *Kwetsbaarheid in beeld*,
maar is ook los te gebruiken, bijvoorbeeld in een spreadsheet of eigen script.

## Wat zit erin

- `data/ncsc-archief.json`: alle adviezen die het NCSC in het CSAF-formaat publiceert (vanaf mei 2024).
  Eén advies per regel, nieuwste eerst.
- `data/csaf-stand.json`: administratie van welke bronbestanden al verwerkt zijn.
- `scripts/bouw_archief.py`: het script dat het archief bouwt en bijwerkt.

Per advies:

| veld | betekenis |
|------|-----------|
| `id` | kenmerk, bijvoorbeeld NCSC-2026-0443 |
| `v`  | versie |
| `d`  | datum eerste publicatie |
| `g`  | datum laatste wijziging |
| `t`  | titel |
| `k`, `s` | kans en schade: L (laag), M (middel), H (hoog) |
| `c`  | CVE-nummers |
| `p`  | getroffen producten |
| `w`  | CWE's (soort kwetsbaarheid) |
| `o`  | samenvatting, ingekort tot 500 tekens |

Het volledige advies staat op `https://advisories.ncsc.nl/advisory?id=<kenmerk>`.

## Hoe het bijgewerkt wordt

Een GitHub Actions-taak (`.github/workflows/archief-bijwerken.yml`) draait elke nacht. Het script leest
`changes.csv` van het NCSC en haalt alleen nieuwe of gewijzigde adviezen op. Zijn er wijzigingen, dan
worden die automatisch vastgelegd. Handmatig starten kan via het tabblad **Actions**, taak
**Archief bijwerken**, knop **Run workflow**.

Lokaal draaien kan ook, alleen Python 3 is nodig:

```
python scripts/bouw_archief.py
```

## Adviezen van voor mei 2024

Oudere adviezen publiceerde het NCSC als ondertekende tekst, niet als CSAF. Die zitten nog niet in dit
archief. Ze kunnen later als apart bestand in hetzelfde formaat worden toegevoegd.

## Bron en gebruik

Bron: [NCSC-NL CSAF-adviezen](https://advisories.ncsc.nl/csaf/v2/), gepubliceerd onder TLP:CLEAR.
Dit archief is een ingekorte kopie voor zoeken en overzicht. Ga voor de volledige en actuele tekst
altijd naar het advies bij het NCSC.
