#!/usr/bin/env python3
import os, sys, json, shlex, datetime
from ipaddress import ip_network, ip_address
import paramiko
from jinja2 import Environment, FileSystemLoader

SSH_HOST = os.getenv("OCF_SSH_HOST", "ssh.ocf.berkeley.edu")
SSH_USER = os.getenv("OCF_SSH_USER")
SSH_PASS = os.getenv("OCF_SSH_PASS")

LDAP_URI = os.getenv("OCF_LDAP_URI", "ldaps://ldap.ocf.berkeley.edu")
LDAP_BASE = os.getenv("OCF_LDAP_BASE", "ou=Hosts,dc=OCF,dc=Berkeley,dc=EDU")
ATTRS = os.getenv("OCF_LDAP_ATTRS", "cn,description,ipHostNumber,ocfHostType,ocfParentHost,objectClass").split(",")

MAIN_BLOCKS = [b.strip() for b in os.getenv("OCF_MAIN_BLOCKS", "").split(",") if b.strip()]

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCS_DIR = os.path.join(REPO_ROOT, "docs")
TPL_DIR = os.path.join(REPO_ROOT, "templates")
OUT_MD = os.path.join(DOCS_DIR, "servers.md")


def _parse_ldif(ldif_text: str):
    unfolded, buf = [], None
    for raw in ldif_text.splitlines():
        if raw.startswith(" "):
            if buf is not None: buf += raw[1:]
        else:
            if buf is not None: unfolded.append(buf)
            buf = raw
    if buf is not None: unfolded.append(buf)

    entries, cur = [], {}
    for line in unfolded + [""]:
        if not line.strip():
            if cur: entries.append(cur); cur = {}
            continue
        if line.lower().startswith("dn:"):
            if cur: entries.append(cur); cur = {}
            cur["dn"] = line.split(":",1)[1].strip()
        else:
            k, v = line.split(":",1)
            k, v = k.strip(), v.strip()
            cur.setdefault(k, []).append(v)
    return entries

def _normalize_ip_list(values):
    out, seen = [], set()
    for v in values or []:
        try:
            ip = str(ip_address(v.strip()))
            if ip not in seen: seen.add(ip); out.append(ip)
        except Exception:
            continue
    return out

def _ldapsearch_over_ssh(filter_str: str, attrs, base, ldap_uri, timeout=25):
    attr_list = " ".join(shlex.quote(a) for a in attrs)
    cmd = (
        f'ldapsearch -x -LLL -o nettimeout={timeout} '
        f'-H {shlex.quote(ldap_uri)} -b {shlex.quote(base)} '
        f'{shlex.quote(filter_str)} {attr_list}'
    )
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(SSH_HOST, username=SSH_USER, password=SSH_PASS, look_for_keys=False, allow_agent=False, timeout=timeout)
    try:
        stdin, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
        out, err = stdout.read().decode(), stderr.read().decode()
        rc = stdout.channel.recv_exit_status()
        return _parse_ldif(out)
    finally:
        cli.close()

def _friendly(entries):
    out = []
    for e in entries:
        def first(key):
            v = e.get(key); 
            return v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else None)
        rec = {
            "dn": e.get("dn"),
            "name": first("cn"),
            "description": first("description"),
            "ips": _normalize_ip_list(e.get("ipHostNumber", [])),
            "type": (first("ocfHostType") or "").lower() or None,
            "parent": first("ocfParentHost"),
            "objectClass": e.get("objectClass", []),
        }
        out.append(rec)
    return out

def _group_hosts_guests(records):
    by_name = {r["name"]: r for r in records if r.get("name")}
    parents = {r["parent"] for r in records if r.get("parent")}
    for p in parents:
        if p in by_name and (by_name[p].get("type") in (None, "unknown", "other")):
            by_name[p]["type"] = "host"

    hosts, others = [], []
    for r in records:
        t = r.get("type") or "unknown"
        parent = r.get("parent")
        if parent and parent in by_name and t != "host":
            r["type"] = "guest" if t in ("unknown","other") else t
            by_name[parent].setdefault("guests", []).append(r)
        elif t == "host":
            hosts.append(r)
        else:
            others.append(r)

    for h in hosts:
        h["guests"] = sorted(h.get("guests", []), key=lambda x: x["name"] or "")
    hosts = sorted(hosts, key=lambda x: x["name"] or "")
    others = sorted(others, key=lambda x: x["name"] or "")
    return hosts, others

def _compute_unassigned(blocks, assigned_ips):
    assigned_v4 = {ip for ip in assigned_ips if "." in ip}
    res = {}
    for cidr in blocks:
        try:
            net = ip_network(cidr, strict=False)
        except Exception:
            continue
        free = []
        for ip in net.hosts():
            s = str(ip)
            if s not in assigned_v4:
                free.append(s)
        res[cidr] = free
    return res


ldif_entries = _ldapsearch_over_ssh("(objectClass=*)", ATTRS, LDAP_BASE, LDAP_URI)
raw = _friendly(ldif_entries)

hosts, others = _group_hosts_guests(raw)

assigned = set(ip for r in raw for ip in r.get("ips", []))
unassigned = _compute_unassigned(MAIN_BLOCKS, assigned)
unassigned_count = sum(len(v) for v in unassigned.values())

env = Environment(loader=FileSystemLoader(TPL_DIR), autoescape=False, trim_blocks=True, lstrip_blocks=True)
tpl = env.get_template("servers.md.j2")
md = tpl.render(
    generated_at=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    hosts=hosts,
    others=others,
    unassigned=unassigned,
    unassigned_count=unassigned_count,
    main_blocks=MAIN_BLOCKS,
)

os.makedirs(DOCS_DIR, exist_ok=True)
with open(OUT_MD, "w") as f:
    f.write(md)
print(f"Wrote {OUT_MD}")

