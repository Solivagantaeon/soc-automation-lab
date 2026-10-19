import json, re, importlib.util, pathlib

ALERTS = '/var/ossec/logs/alerts/alerts.json'
OUT = pathlib.Path('/home/wazadmin/proof/samples/alerts')
WANTED = {
    '86601': 'suricata-86601.json',
    '92910': 'windows-sysmon-92910.json',
    '550':   'fim-550-checksum-changed.json',
    '554':   'fim-554-file-added.json',
    '31103': 'web-31103-sqli.json',
    '31106': 'web-31106-attack-200.json',
}
REPL = [
    (r'SOC-WIN10-01', 'HOST-WIN-01'), (r'SOC-WIN11-AI', 'HOST-WIN-02'),
    (r'SOC-DC01', 'HOST-DC-01'),      (r'SOC-LIN-01', 'HOST-LIN-01'),
    (r'wazuh-master', 'wazuh-manager'), (r'opnsense', 'fw-01'),
    (r'Administrator', 'user01'), (r'soclab', 'example'),
]
ip_map = {}
def anon_ip(m):
    ip = m.group(0)
    ip_map.setdefault(ip, f'192.0.2.{len(ip_map) + 10}')
    return ip_map[ip]

spec = importlib.util.spec_from_file_location('shuffle', '/var/ossec/integrations/shuffle.py')
shuffle = importlib.util.module_from_spec(spec); spec.loader.exec_module(shuffle)

latest = {}
with open(ALERTS, encoding='utf-8', errors='replace') as f:
    for line in f:
        try: a = json.loads(line)
        except ValueError: continue
        rid = a.get('rule', {}).get('id')
        if rid in WANTED: latest[rid] = a

OUT.mkdir(parents=True, exist_ok=True)
for rid, name in WANTED.items():
    if rid not in latest:
        print(f'BRAK  {rid:6} (nie wystąpił w dzisiejszym alerts.json)'); continue
    payload = shuffle.generate_msg(latest[rid], None)
    if not payload:
        print(f'SKIP  {rid:6} (odfiltrowany przez shuffle.py)'); continue
    text = json.dumps(json.loads(payload), indent=2, ensure_ascii=False)
#    for pat, rep in REPL: text = re.sub(pat, rep, text, flags=re.I)
#    text = re.sub(r'\b10\.10\.\d{1,3}\.\d{1,3}\b', anon_ip, text)
    (OUT / name).write_text(text + '\n', encoding='utf-8')
    print(f'OK    {rid:6} -> {name}  ({latest[rid]["timestamp"]})')
