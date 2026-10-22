#!/usr/bin/env python3
"""Bouwt en werkt het archief van NCSC-beveiligingsadviezen bij.

Bron: de openbare CSAF-adviezen van het NCSC (https://advisories.ncsc.nl/csaf/v2/).
Het script leest changes.csv en haalt alleen adviezen op die nieuw of gewijzigd zijn
sinds de vorige keer. De eerste keer worden dus alle CSAF-adviezen opgehaald.

Uitvoer:
  data/ncsc-archief.json  het archief, compact, één advies per regel
  data/csaf-stand.json    per bronbestand de laatst verwerkte wijzigingstijd

Alleen de Python-standaardbibliotheek is nodig.
"""
import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

BASIS = "https://advisories.ncsc.nl/csaf/v2/"
MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
ARCHIEF = os.path.join(MAP, "ncsc-archief.json")
STAND = os.path.join(MAP, "csaf-stand.json")
AGENT = "kwetsbaarheid-in-beeld-archief/1.0 (+https://github.com/speedbird2000/ncsc-archief)"
GELIJKTIJDIG = 4          # bescheiden aantal verzoeken tegelijk
MAX_SAMENVATTING = 500    # tekens
MAX_PRODUCTEN = 50
NIVEAU = {"low": "L", "medium": "M", "high": "H", "laag": "L", "middel": "M", "midden": "M", "hoog": "H"}
ID_PATROON = re.compile(r"^NCSC-\d{4}-\d{4,}$")


def haal(url, pogingen=3):
    """Haalt een adres op, met een paar nieuwe pogingen bij tijdelijke fouten."""
    for poging in range(1, pogingen + 1):
        try:
            verzoek = urllib.request.Request(url, headers={"User-Agent": AGENT})
            with urllib.request.urlopen(verzoek, timeout=60) as antwoord:
                return antwoord.read()
        except Exception as fout:  # noqa: BLE001
            if poging == pogingen:
                raise
            time.sleep(2 * poging)
            print(f"  nieuwe poging voor {url}: {fout}", file=sys.stderr)


def lees_json(pad, standaard):
    try:
        with open(pad, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return standaard


def kort(tekst, maximum):
    tekst = re.sub(r"\s+", " ", tekst or "").strip()
    if len(tekst) <= maximum:
        return tekst
    knip = tekst.rfind(" ", 0, maximum)
    return tekst[: knip if knip > maximum // 2 else maximum].rstrip(" ,.;:") + "..."


def producten(product_tree):
    """Verzamelt productnamen uit de producttak; valt terug op leveranciers als er geen producten zijn."""
    namen, leveranciers = [], []

    def loop(takken):
        for tak in takken or []:
            categorie, naam = tak.get("category"), (tak.get("name") or "").strip()
            if categorie == "product_name" and naam and naam not in namen:
                namen.append(naam)
            elif categorie == "vendor" and naam and naam not in leveranciers:
                leveranciers.append(naam)
            loop(tak.get("branches"))

    loop((product_tree or {}).get("branches"))
    return (namen or leveranciers)[:MAX_PRODUCTEN]


def verwerk(doc):
    """Zet een CSAF-document om naar een compacte archiefregel."""
    d = doc["document"]
    tracking = d["tracking"]
    advies_id = tracking["id"].strip()
    if not ID_PATROON.match(advies_id):
        raise ValueError(f"onverwacht kenmerk: {advies_id}")
    notities = d.get("notes") or []
    algemeen = {(n.get("title") or "").strip().lower(): (n.get("text") or "").strip()
                for n in notities if n.get("category") == "general"}
    beschrijvingen = {(n.get("title") or "").strip().lower(): n.get("text") or ""
                      for n in notities if n.get("category") in ("description", "summary")}
    samenvatting = (beschrijvingen.get("feiten") or beschrijvingen.get("samenvatting")
                    or next(iter(beschrijvingen.values()), ""))
    cwe = [f'{(n.get("title") or "").strip()} {(n.get("text") or "").strip()}'.strip()
           for n in notities if (n.get("title") or "").upper().startswith("CWE-")]
    cves = sorted({(v.get("cve") or "").strip().upper() for v in doc.get("vulnerabilities") or [] if v.get("cve")})
    regel = {
        "id": advies_id,
        "v": tracking.get("version", ""),
        "d": (tracking.get("initial_release_date") or "")[:10],
        "g": (tracking.get("current_release_date") or "")[:10],
        "t": (d.get("title") or "").strip(),
        "k": NIVEAU.get(algemeen.get("kans", "").lower(), ""),
        "s": NIVEAU.get(algemeen.get("schade", "").lower(), ""),
        "c": cves,
        "p": producten(doc.get("product_tree")),
        "w": cwe,
        "o": kort(samenvatting, MAX_SAMENVATTING),
    }
    return {k: v for k, v in regel.items() if v not in ("", [])}


def schrijf_regels(pad, kop, lijst):
    """Schrijft JSON met één advies per regel, zodat wijzigingen in git goed leesbaar zijn."""
    tijdelijk = pad + ".nieuw"
    with open(tijdelijk, "w", encoding="utf-8") as f:
        f.write(json.dumps(kop, ensure_ascii=False)[:-1] + ',"adviezen":[\n')
        f.write(",\n".join(json.dumps(a, ensure_ascii=False, separators=(",", ":")) for a in lijst))
        f.write("\n]}\n")
    os.replace(tijdelijk, pad)


def main():
    os.makedirs(MAP, exist_ok=True)
    stand = lees_json(STAND, {})
    bestaand = lees_json(ARCHIEF, {"adviezen": []})
    archief = {a["id"]: a for a in bestaand.get("adviezen", [])}

    wijzigingen = list(csv.reader(io.StringIO(haal(BASIS + "changes.csv").decode("utf-8"))))
    te_doen = [(pad, tijd) for pad, tijd in (r[:2] for r in wijzigingen if len(r) >= 2)
               if pad.endswith(".json") and stand.get(pad) != tijd]
    print(f"{len(wijzigingen)} bestanden in changes.csv, {len(te_doen)} nieuw of gewijzigd")

    def een(paar):
        pad, tijd = paar
        try:
            inhoud = haal(BASIS + pad)
        except Exception as fout:  # noqa: BLE001
            return pad, tijd, None, "ophalen", fout
        try:
            return pad, tijd, verwerk(json.loads(inhoud)), None, None
        except Exception as fout:  # noqa: BLE001
            return pad, tijd, None, "verwerken", fout

    gelukt = onbereikbaar = onleesbaar = 0
    with ThreadPoolExecutor(max_workers=GELIJKTIJDIG) as pool:
        for pad, tijd, regel, soort, fout in pool.map(een, te_doen):
            if soort == "ophalen":
                # Volgende keer opnieuw proberen.
                onbereikbaar += 1
                print(f"  niet opgehaald {pad}: {fout}", file=sys.stderr)
                continue
            # Een onleesbaar bestand wordt pas opnieuw geprobeerd als het NCSC het aanpast.
            stand[pad] = tijd
            if soort == "verwerken":
                onleesbaar += 1
                print(f"  onleesbaar, overgeslagen {pad}: {fout}", file=sys.stderr)
                continue
            archief[regel["id"]] = regel
            gelukt += 1
    print(f"verwerkt: {gelukt}, niet opgehaald: {onbereikbaar}, onleesbaar: {onleesbaar}, totaal in archief: {len(archief)}")

    if onbereikbaar and onbereikbaar == len(te_doen):
        sys.exit("Geen enkel advies kon worden opgehaald; mogelijk is de NCSC-site onbereikbaar.")
    if not gelukt and not onleesbaar:
        return

    lijst = sorted(archief.values(), key=lambda a: a["id"], reverse=True)
    kop = {
        "bron": "NCSC-NL, CSAF-adviezen (" + BASIS + ")",
        "bijgewerkt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aantal": len(lijst),
        "velden": {"id": "kenmerk", "v": "versie", "d": "eerste publicatie", "g": "laatst gewijzigd",
                   "t": "titel", "k": "kans (L/M/H)", "s": "schade (L/M/H)", "c": "CVE's",
                   "p": "producten", "w": "CWE's", "o": "samenvatting (ingekort)"},
    }
    schrijf_regels(ARCHIEF, kop, lijst)
    with open(STAND, "w", encoding="utf-8") as f:
        json.dump(dict(sorted(stand.items())), f, ensure_ascii=False, indent=0)
        f.write("\n")


if __name__ == "__main__":
    main()
