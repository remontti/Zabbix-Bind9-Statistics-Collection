#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __author__ = 'https://github.com/remontti/Zabbix-Bind9-Statistics-Collection'

import json
import os
import sys
import time
import re
import http.client
import xml.etree.ElementTree as ElementTree

JSONFILE = "/tmp/zabbix/bindstats.json"
CACHELIFE = 60


def parse_args():
    """
    Parser simples para evitar qualquer SystemExit/traceback do argparse.
    Uso:
      bind-stats-rr.py <action> [-z zone] [-c counter] [-p port] [-m]
    """
    if len(sys.argv) < 2:
        return {"action": None, "z": None, "c": None, "p": None, "m": False}

    args = {
        "action": sys.argv[1],
        "z": None,
        "c": None,
        "p": None,
        "m": False,
    }

    it = iter(sys.argv[2:])
    for token in it:
        if token == "-z":
            try:
                args["z"] = next(it)
            except StopIteration:
                break
        elif token == "-c":
            try:
                args["c"] = next(it)
            except StopIteration:
                break
        elif token == "-p":
            try:
                args["p"] = int(next(it))
            except (StopIteration, ValueError):
                args["p"] = None
        elif token == "-m":
            args["m"] = True
        # qualquer outro parâmetro é ignorado silenciosamente

    return args


def load_cache():
    if not os.path.exists(JSONFILE):
        return None

    if time.time() - os.path.getmtime(JSONFILE) > CACHELIFE:
        return None

    try:
        with open(JSONFILE) as f:
            data = json.load(f)
        # valida estrutura básica
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        # cache inexistente/corrompido → força nova coleta
        return None


def fetch_bind_stats(port: int) -> bytes:
    conn = http.client.HTTPConnection("localhost", port, timeout=5)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"HTTP GET failed, status {resp.status}")
        return resp.read()
    finally:
        conn.close()


def detect_stats_version(root) -> int:
    # layout antigo
    if root.tag == "isc":
        node = root.find("./bind/statistics")
        if node is None or "version" not in node.attrib:
            raise RuntimeError("Cannot find statistics version in <isc> tree")
        version_str = node.attrib["version"]

    # layout novo
    elif root.tag == "statistics":
        if "version" not in root.attrib:
            raise RuntimeError("Cannot find statistics version in <statistics> root")
        version_str = root.attrib["version"]

    else:
        raise RuntimeError(f"Unknown root tag: {root.tag}")

    m = re.match(r"^(\d+)", version_str)
    if not m:
        raise RuntimeError(f"Cannot parse statistics version: {version_str}")

    major = int(m.group(1))

    # Aceitamos v2 e v3+. v3+ é tratado como layout v3.
    if major < 2:
        raise RuntimeError(f"Unsupported bind statistics version: {version_str}")

    if major >= 3:
        return 3
    return 2


def build_cache_from_xml(content: bytes) -> dict:
    root = ElementTree.fromstring(content)
    version = detect_stats_version(root)

    j = {
        "zones": {},
        "counter": {},
        "zonemaintenancecounter": {},
        "resolvercounter": {},
        "socketcounter": {},
        "incounter": {},
        "outcounter": {},
        "cache": {},
        "memory": {},
    }

    # Versão 2 (layout antigo)
    if version == 2:
        for view in root.iterfind("./bind/statistics/views/view"):
            if view.findtext("./name") in ("_default",):
                for zone in view.iterfind("./zones/zone"):
                    if zone.find("./counters") is not None:
                        counters = {}
                        for counter in zone.iterfind("./counters/*"):
                            counters[counter.tag] = counter.text
                        j["zones"][zone.findtext("./name")] = counters

        for stat in root.iterfind("./bind/statistics/server/nsstat"):
            j["counter"][stat.findtext("./name")] = stat.findtext("./counter")

        for stat in root.iterfind("./bind/statistics/server/zonestat"):
            j["zonemaintenancecounter"][stat.findtext("./name")] = stat.findtext("./counter")

        for view in root.iterfind("./bind/statistics/views/view"):
            if view.findtext("./name") in ("_default",):
                for stat in view.iterfind("./resstat"):
                    j["resolvercounter"][stat.findtext("./name")] = stat.findtext("./counter")

        for stat in root.iterfind("./bind/statistics/server/sockstat"):
            j["socketcounter"][stat.findtext("./name")] = stat.findtext("./counter")

        for stat in root.iterfind("./bind/statistics/server/queries-in/rdtype"):
            j["incounter"][stat.findtext("./name")] = stat.findtext("./counter")

        for stat in root.iterfind("./bind/statistics/views/view/rdtype"):
            j["outcounter"][stat.findtext("./name")] = stat.findtext("./counter")

        for child in root.iterfind("./bind/statistics/memory/summary/*"):
            j["memory"][child.tag] = child.text

        for child in root.iterfind("./bind/statistics/views/view/cache"):
            if child.attrib.get("name") == "localhost_resolver":
                for stat in child.iterfind("./rrset"):
                    j["cache"][stat.findtext("./name")] = stat.findtext("./counter")

    # Versão 3+ (layout novo)
    else:
        for child in root.iterfind("./server/counters"):
            ctype = child.attrib.get("type")
            if ctype == "nsstat":
                for stat in child.iterfind("./counter"):
                    j["counter"][stat.attrib["name"]] = stat.text
            elif ctype == "sockstat":
                for stat in child.iterfind("./counter"):
                    j["socketcounter"][stat.attrib["name"]] = stat.text
            elif ctype == "zonestat":
                for stat in child.iterfind("./counter"):
                    j["zonemaintenancecounter"][stat.attrib["name"]] = stat.text
            elif ctype == "qtype":
                for stat in child.iterfind("./counter"):
                    j["incounter"][stat.attrib["name"]] = stat.text

        for defroot in root.iterfind("./views/"):
            if defroot.attrib.get("name") == "_default":
                for child in defroot.iterfind("./counters"):
                    ctype = child.attrib.get("type")
                    if ctype == "resqtype":
                        for stat in child.iterfind("./counter"):
                            j["outcounter"][stat.attrib["name"]] = stat.text
                    elif ctype == "resstats":
                        for stat in child.iterfind("./counter"):
                            j["resolvercounter"][stat.attrib["name"]] = stat.text
                    elif ctype == "cachestats":
                        for stat in child.iterfind("./counter"):
                            j["cache"][stat.attrib["name"]] = stat.text

        for child in root.iterfind("./views/view/cache"):
            if child.attrib.get("name") == "_default":
                for stat in child.iterfind("./rrset"):
                    name = stat.findtext("./name")
                    counter = stat.findtext("./counter")
                    if name is None:
                        continue
                    j["cache"][name] = counter
                    if re.match(r"^!", name):
                        j["cache"][name.replace("!", "_")] = counter

        for child in root.iterfind("./views/view"):
            if child.attrib.get("name") == "_default":
                for zone in child.iterfind("./zones/zone"):
                    counters = {}
                    for stat in zone.iterfind("./counters"):
                        stype = stat.attrib.get("type")
                        if stype in ("rcode", "qtype"):
                            for counter in stat.iterfind("./counter"):
                                counters[counter.attrib["name"]] = counter.text
                    j["zones"][zone.attrib["name"]] = counters

        for child in root.iterfind("./memory/summary/*"):
            j["memory"][child.tag] = child.text

    os.makedirs(os.path.dirname(JSONFILE), exist_ok=True)
    with open(JSONFILE, "w") as f:
        json.dump(j, f)

    return j


def run_action(args, j):
    action = args["action"]

    if not action:
        print("ZBX_NOTSUPPORTED")
        return

    if action == "discoverzones":
        d = {
            "data": [
                {"{#ZONE}": zone}
                for zone in j.get("zones", {}).keys()
                if len(j["zones"][zone]) > 0
            ]
        }
        print(json.dumps(d))
        return

    if action == "zonecounter":
        if not (args["z"] and args["c"]):
            print("ZBX_NOTSUPPORTED")
            return
        if args["z"] in j.get("zones", {}) and args["c"] in j["zones"][args["z"]]:
            print(j["zones"][args["z"]][args["c"]])
        else:
            print("ZBX_NOTSUPPORTED")
        return

    if action == "jsonzone":
        if not args["z"]:
            print("ZBX_NOTSUPPORTED")
            return
        if args["z"] in j.get("zones", {}):
            print(json.dumps(j["zones"][args["z"]]))
        else:
            print("ZBX_NOTSUPPORTED")
        return

    if action == "json":
        j_copy = dict(j)
        j_copy.pop("zones", None)
        search = j_copy.get("resolvercounter", {})

        for k in list(search.keys()):
            if "+" in k:
                nkey = k.replace("+", "PLUS")
                j_copy["resolvercounter"][nkey] = search[k]

        print(json.dumps(j_copy))
        return

    # demais ações: counter, zonemaintenancecounter, resolvercounter, socketcounter, incounter, outcounter, cache, memory
    if not args["c"]:
        print("ZBX_NOTSUPPORTED")
        return

    if action not in j or args["c"] not in j[action]:
        print("ZBX_NOTSUPPORTED")
        return

    if not args["m"]:
        print(j[action][args["c"]])
    else:
        key = f"{args['c']}+"
        print(j[action].get(key, "0"))


def main():
    args = parse_args()

    # Porta configurável
    port = args["p"] if args["p"] else 58053

    j = load_cache()
    if j is None:
        content = fetch_bind_stats(port)
        j = build_cache_from_xml(content)

    run_action(args, j)


if __name__ == "__main__":
    # Qualquer erro aqui é convertido em saída controlada.
    try:
        main()
    except Exception:
        # Nada de traceback, nunca.
        if len(sys.argv) > 1 and sys.argv[1] == "json":
            # item master JSON sempre recebe JSON válido
            print("{}")
        else:
            print("ZBX_NOTSUPPORTED")
        sys.exit(1)

