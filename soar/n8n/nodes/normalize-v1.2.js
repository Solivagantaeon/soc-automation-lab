
/**
 * SOC - Wazuh Alert Normalization
 * Stage: Normalize (#67)
 * Version: 1.2
 *
 * Supported input formats:
 * - Raw Wazuh alert
 * - Elasticsearch document (_source)
 * - Shuffle wrapper (all_fields)
 *
 * Output:
 * - Unified alert metadata
 * - Typed observables
 * - Primary observable
 * - Deduplication key
 *
 * n8n Code node:
 * Mode: Run Once for All Items
 */

// ============================================================
// 1. INPUT
// ============================================================

const items = $input.all();

// ============================================================
// 2. HELPERS
// ============================================================

function get(obj, path) {
  return path.split('.').reduce(
    (value, key) => value == null ? undefined : value[key],
    obj
  );
}

function normalizePath(value) {
  return typeof value === 'string'
    ? value.replace(/\\\\/g, '\\')
    : value;
}

// IPv4 validation
function isIPv4(value) {
  if (typeof value !== 'string') return false;

  const parts = value.split('.');

  return parts.length === 4 && parts.every(part =>
    /^\d{1,3}$/.test(part) &&
    Number(part) >= 0 &&
    Number(part) <= 255
  );
}

// IPv6 validation, including compressed and IPv4-mapped forms
function isIPv6(value) {
  if (typeof value !== 'string' || !value.includes(':')) {
    return false;
  }

  let ip = value.toLowerCase();

  // Zone identifiers are not handled
  if (ip.includes('%')) return false;

  // Convert an embedded IPv4 tail into two IPv6 groups
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');

    if (lastColon === -1 ||
        !isIPv4(ip.slice(lastColon + 1))) {
      return false;
    }

    ip = ip.slice(0, lastColon) + ':0:0';
  }

  const doubleColon = ip.indexOf('::');

  if (doubleColon !== -1) {
    // Only one :: is allowed
    if (ip.indexOf('::', doubleColon + 2) !== -1) {
      return false;
    }

    const parts = ip.split('::');

    const left = parts[0]
      ? parts[0].split(':')
      : [];

    const right = parts[1]
      ? parts[1].split(':')
      : [];

    const groups = [...left, ...right];

    if (!groups.every(group => /^[0-9a-f]{1,4}$/i.test(group))) {
      return false;
    }

    // :: must replace at least one group
    return groups.length < 8;
  }

  const groups = ip.split(':');

  return groups.length === 8 &&
    groups.every(group => /^[0-9a-f]{1,4}$/i.test(group));
}

function isIP(value) {
  return isIPv4(value) || isIPv6(value);
}

// Private, loopback and link-local IP detection
function isPrivateIP(ip) {
  if (isIPv4(ip)) {
    const p = ip.split('.').map(Number);

    return p[0] === 10 ||
      p[0] === 127 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 169 && p[1] === 254);
  }

  if (isIPv6(ip)) {
    const value = ip.toLowerCase();

    return value === '::' ||
      value === '::1' ||
      /^f[cd]/i.test(value) ||
      /^fe[89ab]/i.test(value);
  }

  return false;
}

// Domain validation
function isDomain(value) {
  if (typeof value !== 'string') return false;

  const domain = value.toLowerCase().replace(/\.$/, '');

  if (domain.length > 253 || domain.includes('://')) {
    return false;
  }

  if (isIP(domain)) return false;

  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain);
}

// Hash validation
function isValidHash(value) {
  return typeof value === 'string' &&
    (
      /^[a-f0-9]{32}$/i.test(value) ||
      /^[a-f0-9]{40}$/i.test(value) ||
      /^[a-f0-9]{64}$/i.test(value)
    );
}

// Windows Registry detection
function isRegistryPath(value) {
  return typeof value === 'string' &&
    /^(HKEY_|HKLM\\|HKCU\\|HKCR\\|HKU\\|HKCC\\)/i.test(value);
}

// ============================================================
// 3. NORMALIZATION
// ============================================================

function normalizeAlert(root) {

  const body = root.body ?? root;

  // Detect input format
  const alert =
    body._source ??
    body.all_fields ??
    body;

  if (!alert.rule || alert.rule.id === undefined) {
    throw new Error(
      'Invalid Wazuh alert: missing rule.id'
    );
  }

  const observables = [];
  const seen = new Set();

  // ----------------------------------------------------------
  // Add observable with deduplication
  // ----------------------------------------------------------

  function add(dataType, value, field, extra = {}) {
    if (value === undefined || value === null) return;

    const data = String(value).trim();

    if (!data || data === '-' || data === '(null)') {
      return;
    }

    const key = `${dataType}|${data.toLowerCase()}`;

    if (seen.has(key)) return;

    seen.add(key);

    observables.push({
      dataType,
      data,
      field,
      internal: false,
      ...extra
    });
  }

  // ==========================================================
  // 4. IP ADDRESSES
  // ==========================================================

  const ipFields = [
    'data.srcip',
    'data.src_ip',
    'data.dstip',
    'data.dest_ip',
    'data.win.eventdata.sourceIp',
    'data.win.eventdata.destinationIp',
    'data.win.eventdata.ipAddress',
    'agent.ip'
  ];

  for (const field of ipFields) {
    const value = get(alert, field);

    if (typeof value === 'string' && isIP(value)) {
      add('ip', value, field, {
        internal: isPrivateIP(value)
      });
    }
  }

  // ==========================================================
  // 5. DOMAINS
  // ==========================================================

  const domainFields = [
    'data.win.eventdata.queryName',
    'data.dns.rrname',
    'data.http.hostname',
    'data.tls.sni'
  ];

  for (const field of domainFields) {
    const value = get(alert, field);

    if (typeof value === 'string' && isDomain(value)) {
      const domain = value.toLowerCase().replace(/\.$/, '');

      add('domain', domain, field, {
        internal: /\.(lab|local|lan|internal|localdomain)$/.test(domain)
      });
    }
  }

  // ==========================================================
  // 6. URLS
  // ==========================================================

  const httpHost = get(alert, 'data.http.hostname');

  for (const field of [
    'data.url',
    'data.http.url'
  ]) {
    const value = get(alert, field);

    if (typeof value !== 'string' || !value.trim()) {
      continue;
    }

    if (/^https?:\/\//i.test(value)) {
      add('url', value, field);

    } else if (
      field === 'data.http.url' &&
      typeof httpHost === 'string'
    ) {
      add(
        'url',
        `http://${httpHost}${value.startsWith('/') ? '' : '/'}${value}`,
        field
      );

    } else {
      add('uri_path', value, field);
    }
  }

  // ==========================================================
  // 7. HASHES
  // ==========================================================

  const hashes = get(alert, 'data.win.eventdata.hashes');

  if (typeof hashes === 'string') {
    for (const part of hashes.split(',')) {
      const separator = part.indexOf('=');

      if (separator === -1) continue;

      const algorithm = part
        .slice(0, separator)
        .trim()
        .toUpperCase();

      const value = part
        .slice(separator + 1)
        .trim()
        .toLowerCase();

      const lengths = {
        MD5: 32,
        SHA1: 40,
        SHA256: 64
      };

      if (
        lengths[algorithm] === value.length &&
        isValidHash(value)
      ) {
        add(
          'hash',
          value,
          'data.win.eventdata.hashes',
          { algorithm }
        );
      }
    }
  }

  // Syscheck hashes
  for (const [field, algorithm] of [
    ['syscheck.sha256_after', 'SHA256'],
    ['syscheck.sha1_after', 'SHA1'],
    ['syscheck.md5_after', 'MD5']
  ]) {
    const value = get(alert, field);

    if (
      typeof value === 'string' &&
      isValidHash(value)
    ) {
      add('hash', value.toLowerCase(), field, {
        algorithm
      });
    }
  }

  // ==========================================================
  // 8. FILENAMES AND FILE PATHS
  // ==========================================================

  for (const field of [
    'data.win.eventdata.image',
    'data.win.eventdata.targetFilename',
    'syscheck.path'
  ]) {
    const value = normalizePath(get(alert, field));

    if (typeof value !== 'string' || !value.trim()) {
      continue;
    }

    // Registry paths are handled separately
    if (isRegistryPath(value)) continue;

    const filename = value.split(/[\\/]/).pop();

    // Accept filenames with and without extensions
    if (filename) {
      add('filename', filename, field, {
        path: value
      });
    }
  }

  // ==========================================================
  // 9. WINDOWS REGISTRY
  // ==========================================================

  const registryPath = normalizePath(
    get(alert, 'syscheck.path')
  );

  if (isRegistryPath(registryPath)) {
    add(
      'registry_key',
      registryPath,
      'syscheck.path',
      { internal: true }
    );
  }

  // ==========================================================
  // 10. USER ACCOUNTS
  // ==========================================================

  const userFields = [
    'data.win.eventdata.user',
    'data.win.eventdata.targetUserName',
    'data.srcuser',
    'data.dstuser',
    'syscheck.uname_after'
  ];

  for (const field of userFields) {
    const value = normalizePath(get(alert, field));

    if (typeof value === 'string') {
      add('other', value, field, {
        kind: 'user',
        internal: true
      });
    }
  }

  // ==========================================================
  // 11. USER-AGENT
  // ==========================================================

  const userAgentFields = [
    'data.http.http_user_agent',
    'data.http.user_agent'
  ];

  for (const field of userAgentFields) {
    const value = get(alert, field);

    if (typeof value === 'string') {
      add('user-agent', value, field);
    }
  }

  // ==========================================================
  // 12. HOSTNAME
  // ==========================================================

  if (alert.agent?.name) {
    add(
      'hostname',
      alert.agent.name,
      'agent.name',
      { internal: true }
    );
  }

  // ==========================================================
  // 13. PRIMARY OBSERVABLE
  // ==========================================================

  const pick = predicate =>
    observables.find(predicate)?.data;

  const primary =
    pick(o => o.dataType === 'ip' && !o.internal) ??
    pick(o => o.dataType === 'hash') ??
    pick(o => o.dataType === 'domain' && !o.internal) ??
    pick(o => o.dataType === 'filename') ??
    pick(o => o.dataType === 'registry_key') ??
    pick(o => o.dataType === 'uri_path') ??
    '-';

  // ==========================================================
  // 14. DEDUPLICATION KEY
  // ==========================================================

  const ruleId = String(alert.rule.id);

  const agentId = String(
    alert.agent?.id ?? 'na'
  );

  const signatureId =
    get(alert, 'data.alert.signature_id') ?? '';

  const dedupKey = [
    'soc:dedup',
    ruleId,
    signatureId,
    agentId,
    primary
  ].join(':').slice(0, 300);

  // ==========================================================
  // 15. NORMALIZED OUTPUT
  // ==========================================================

  const mitre = alert.rule.mitre ?? {};

  const sourceFormat =
    body._source || root._source
      ? 'elasticsearch'
      : body.all_fields
        ? 'shuffle-wrapper'
        : 'raw';

  return {
    alert_id:
      alert.id ??
      body._id ??
      root._id ??
      null,

    timestamp: alert.timestamp ?? null,

    manager: alert.manager?.name ?? 'wazuh',

    source_format: sourceFormat,

    rule: {
      id: ruleId,
      level: Number(alert.rule.level ?? 0),
      description: alert.rule.description ?? '',
      groups: alert.rule.groups ?? [],
      mitre_ids: mitre.id ?? [],
      mitre_tactics: mitre.tactic ?? [],
      mitre_techniques: mitre.technique ?? [],
      firedtimes: alert.rule.firedtimes ?? null
    },

    agent: {
      id: agentId,
      name: alert.agent?.name ?? 'unknown',
      ip: alert.agent?.ip ?? null
    },

    location: alert.location ?? null,

    decoder: alert.decoder?.name ?? null,

    syscheck: alert.syscheck ?? null,

    signature: get(alert, 'data.alert.signature') ?? null,

    command_line: normalizePath(
      get(alert, 'data.win.eventdata.commandLine')
    ) ?? null,

    full_log:
      typeof alert.full_log === 'string'
        ? alert.full_log.slice(0, 2000)
        : null,

    observables,

    primary_observable: primary,

    dedup_key: dedupKey
  };
}

// ============================================================
// 16. PROCESS ALL INPUT ITEMS
// ============================================================

return items.map(item => ({
  json: normalizeAlert(item.json)
}));
