const INTERNAL_DOMAIN_SUFFIXES = [
  'lab',
  'local',
  'lan',
  'internal',
  'localdomain',
  'localhost',
  'test',
  'invalid',
  'home.arpa',
];

function parseIPv4(value) {
  const parts = String(value).split('.');

  if (
    parts.length !== 4 ||
    parts.some((part) => !/^\d{1,3}$/.test(part))
  ) {
    return null;
  }

  const numbers = parts.map(Number);

  if (numbers.some((part) => part < 0 || part > 255)) {
    return null;
  }

  return numbers;
}

function isNonPublicIPv4(parts) {
  const [a, b, c] = parts;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isNonPublicOrInvalidIPv6(value) {
  const address = String(value)
    .replace(/^\[|\]$/g, '')
    .split('%')[0]
    .toLowerCase();

  if (!address.includes(':')) return true;

  const doubleColonCount = (address.match(/::/g) ?? []).length;
  const groups = address.split(':').filter(Boolean);

  if (
    doubleColonCount > 1 ||
    address.includes('.') ||
    groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group)) ||
    (doubleColonCount === 0 && groups.length !== 8) ||
    (doubleColonCount === 1 && groups.length >= 8)
  ) {
    return true;
  }

  const firstGroup = groups[0];
  if (!firstGroup) return true;

  const first = Number.parseInt(firstGroup, 16);

  // Allow only IPv6 global-unicast space (2000::/3).
  if (first < 0x2000 || first > 0x3fff) return true;

  // Documentation-only IPv6 range.
  if (/^2001:db8(?::|$)/.test(address)) return true;

  return false;
}

function hostSkipReason(rawHost) {
  let host = String(rawHost ?? '')
    .trim()
    .replace(/^\[|\]$/g, '');

  if (!host) return 'Missing URL host';

  if (host.includes(':')) {
    return isNonPublicOrInvalidIPv6(host)
      ? 'Non-public or invalid IPv6 host'
      : null;
  }

  if (/[\/?#@\s\\]/.test(host)) {
    return 'Invalid hostname';
  }

  host = host.replace(/\.$/, '').toLowerCase();

  const ipv4 = parseIPv4(host);

  if (ipv4) {
    return isNonPublicIPv4(ipv4) ? 'Non-public IPv4 host' : null;
  }

  if (/^[\d.]+$/.test(host)) {
    return 'Invalid or non-public IP host';
  }

  if (!host.includes('.')) {
    return 'Single-label or local hostname';
  }

  const labels = host.split('.');

  if (
    labels.some(
      (label) =>
        !label ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    return 'Invalid hostname';
  }

  if (
    INTERNAL_DOMAIN_SUFFIXES.some(
      (suffix) => host === suffix || host.endsWith(`.${suffix}`),
    )
  ) {
    return 'Local or internal domain suffix';
  }

  return null;
}

function urlSkipReason(value) {
  const input = String(value ?? '').trim();

  if (!input || /[\s\\]/.test(input)) {
    return 'Invalid URL';
  }

  const schemeMatch = input.match(/^([a-z][a-z0-9+.-]*):\/\//i);

  if (!schemeMatch) {
    return 'Invalid URL';
  }

  const scheme = schemeMatch[1].toLowerCase();

  if (!['http', 'https'].includes(scheme)) {
    return 'Unsupported URL scheme';
  }

  const authority = input
    .slice(schemeMatch[0].length)
    .split(/[/?#]/, 1)[0];

  if (!authority) {
    return 'Missing URL host';
  }

  if (authority.includes('@')) {
    return 'URL contains credentials';
  }

  let host;

  function isValidPort(port) {
    return /^\d{1,5}$/.test(port) && Number(port) <= 65535;
  }

  if (authority.startsWith('[')) {
    const closingBracket = authority.indexOf(']');

    if (closingBracket < 0) {
      return 'Invalid URL';
    }

    host = authority.slice(1, closingBracket);
    const portSuffix = authority.slice(closingBracket + 1);

    if (
      portSuffix &&
      (!portSuffix.startsWith(':') ||
        !isValidPort(portSuffix.slice(1)))
    ) {
      return 'Invalid URL';
    }
  } else {
    const colonCount = (authority.match(/:/g) ?? []).length;

    if (colonCount > 1) {
      return 'Invalid URL';
    }

    const colonIndex = authority.lastIndexOf(':');

    if (colonIndex >= 0) {
      host = authority.slice(0, colonIndex);
      const port = authority.slice(colonIndex + 1);

      if (!isValidPort(port)) {
        return 'Invalid URL';
      }
    } else {
      host = authority;
    }
  }

  return hostSkipReason(host);
}

function ipSkipReason(value) {
  const candidate = String(value ?? '')
    .trim()
    .replace(/^\[|\]$/g, '');

  const ipv4 = parseIPv4(candidate);

  if (ipv4) {
    return isNonPublicIPv4(ipv4) ? 'Non-public IPv4 address' : null;
  }

  if (candidate.includes(':')) {
    return isNonPublicOrInvalidIPv6(candidate)
      ? 'Non-public or invalid IPv6 address'
      : null;
  }

  return 'Invalid IP address';
}

const observable = $json ?? {};
const type = String(observable.type ?? '').trim().toLowerCase();
const value = String(observable.value ?? '').trim();

let reason = null;

if (!type || !value) {
  reason = 'Missing observable type or value';
} else if (
  observable.internal === true ||
  String(observable.internal).toLowerCase() === 'true'
) {
  reason = 'Marked internal by normalization';
} else if (type === 'ip') {
  reason = ipSkipReason(value);
} else if (type === 'domain') {
  reason = hostSkipReason(value);
} else if (type === 'url') {
  reason = urlSkipReason(value);
} else if (type !== 'hash') {
  reason = 'Unsupported Cortex observable type';
}

return {
  json: {
    ...observable,
    type,
    value,
    cortex_eligible: reason === null,
    cortex_skip_reason: reason,
  },
};
