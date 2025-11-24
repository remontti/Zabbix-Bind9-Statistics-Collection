#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __author__ = 'https://github.com/remontti/Zabbix-Bind9-Statistics-Collection'

import argparse
import json
import os
import sys
import time
import re
import http.client
import xml.etree.ElementTree as ElementTree

JSONFILE = '/tmp/zabbix/bindstats.json'
CACHELIFE = 60


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        help=(
            "discoverzones | counter | zonecounter | zonemaintenancecounter | "
            "resolvercounter | socketcounter | incounter | outcounter | json"
        ),
    )
    parser.add_argument("-z", help="zone")
    parser.add_argument("-c", help="counter name")
    parser.add_argument("-p", help="bind stats port")
    parser.add_argument("-m", help="add plus")
    return parser.parse_args()


def load_cache():
    if not os.path.exists(JSONFILE):
        return None
    if time.time() - os.path.getmtime(JSONFILE) > CACHELIFE:
        return None
    try:
        with open(JSONFILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        # cache corrompido ou vazio
        return None


def fetch_bind_stats(port: int) -> bytes:
    conn = http.client.HTTPConnection("localhost", port)
    conn.request("GET", "/")
    resp = conn.getresponse()
    if resp.status != 200:
        print("HTTP GET Failed", file=sys.stderr)
        sys.exit(1)
    content = resp.read()
    conn.close()
    return content


def detect_stats_version(root) -> int:
    # BIND estilo antigo
    if root.tag == "isc":
        node = root.find("./bind/statistics")
        if node is None or "version" not in node.attrib:
            print("Cannot find statistics version in <isc> tree", file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)
        version_str = node.attrib["version"]

    # BIND 9.10+ estilo novo
    elif root.tag == "statistics":
        if "version" not in root.attrib:
            print("Cannot find statistics version in <statistics> root", file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)
        version_str = root.attrib["version"]

    else:
        print("Unknown root tag: {}".format(root.tag), file=sys.stderr)
        print("ZBX_NOTSUPPORTED")
        sys.exit(1)

    m = re.match(r"^(\d+)", version_str)
    if not m:
        print("Cannot parse statistics version: {}".format(version_str), file=sys.stderr)
        print("ZBX_NOTSUPPORTED")
        sys.exit(1)

    major = int(m.group(1))

    # Aceita v2 (legacy) e v3+ (tratando como v3, layout compatível nas versões atuais)
    if major < 2:
        print("Unsupported bind statistics version: {}".format(version_str), file=sys.stderr)
        print("ZBX_NOTSUPPORTED")
        sys.exit(1)

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

    # Layout antigo (v2)
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

        # Memory
        for child in root.iterfind("./bind/statistics/memory/summary/*"):
            j["memory"][child.tag] = child.text

        # Cache para localhost_resolver
        for child in root.iterfind("./bind/statistics/views/view/cache"):
            if child.attrib.get("name") == "localhost_resolver":
                for stat in child.iterfind("./rrset"):
                    j["cache"][stat.findtext("./name")] = stat.findtext("./counter")

    # Layout novo (v3+ tratado como v3)
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

        # Apenas view _default
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

        # Cache rrsets
        for child in root.iterfind("./views/view/cache"):
            if child.attrib.get("name") == "_default":
                for stat in child.iterfind("./rrset"):
                    name = stat.findtext("./name")
                    counter = stat.findtext("./counter")
                    if name is None:
                        continue
                    j["cache"][name] = counter
                    # Para sets começando com '!', troca por '_'
                    if re.match(r"^!", name):
                        j["cache"][name.replace("!", "_")] = counter

        # Zone stats
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

        # Memory
        for child in root.iterfind("./memory/summary/*"):
            j["memory"][child.tag] = child.text

    # Garante diretório e grava cache
    os.makedirs(os.path.dirname(JSONFILE), exist_ok=True)
    with open(JSONFILE, "w") as f:
        json.dump(j, f)

    return j


def main():
    args = parse_args()

    # Porta configurável
    port = 58053
    if args.p:
        try:
            port = int(args.p)
        except ValueError:
            print("Invalid port: {}".format(args.p), file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)

    j = load_cache()
    if j is None:
        content = fetch_bind_stats(port)
        j = build_cache_from_xml(content)

    action = args.action

    if action == "discoverzones":
        d = {
            "data": [
                {"{#ZONE}": zone}
                for zone in j["zones"].keys()
                if len(j["zones"][zone]) > 0
            ]
        }
        print(json.dumps(d))
        sys.exit(0)

    elif action == "zonecounter":
        if not (args.z and args.c):
            print("Missing argument", file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)
        if args.z in j["zones"] and args.c in j["zones"][args.z]:
            print(j["zones"][args.z][args.c])
            sys.exit(0)
        else:
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)

    elif action == "jsonzone":
        if not args.z:
            print("Missing argument", file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)
        if args.z in j["zones"]:
            print(json.dumps(j["zones"][args.z]))
            sys.exit(0)
        else:
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)

    elif action == "json":
        # Comportamento original: remove 'zones', trata resolvercounter com '+'
        if "zones" in j:
            del j["zones"]
        tmp = j
        search = j.get("resolvercounter", {})

        for k in list(search.keys()):
            # procura '+'
            key = re.findall(r"\+", k)
            if key:
                nkey = k.replace("+", "PLUS")
                tmp["resolvercounter"][nkey] = search[k]
                print(json.dumps(tmp))
                sys.exit(0)

        # se não houver '+', retorna json mesmo assim
        print(json.dumps(tmp))
        sys.exit(0)

    else:
        # contador genérico
        if not args.c:
            print("Missing argument", file=sys.stderr)
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)

        if action not in j or args.c not in j[action]:
            print("ZBX_NOTSUPPORTED")
            sys.exit(1)

        if not args.m:
            print(j[action][args.c])
        else:
            # mesmo efeito que antes: usa chave 'nome+'
            key = "{}+".format(args.c)
            print(j[action].get(key, "0"))
        sys.exit(0)


if __name__ == "__main__":
    main()
