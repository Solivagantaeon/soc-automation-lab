const items = $input.all();
const seen = new Map();
const output = [];

function isInternal(value) {
  return value === true || String(value ?? '').toLowerCase() === 'true';
}

for (const item of items) {
  const observable = item.json ?? {};

  const nested =
    observable.observables &&
    typeof observable.observables === 'object' &&
    !Array.isArray(observable.observables)
      ? observable.observables
      : {};

  const type = String(
    observable.type ?? nested.type ?? nested.dataType ?? ''
  ).trim().toLowerCase();

  let value = String(
    observable.value ?? nested.value ?? nested.data ?? ''
  ).trim();

  const field = observable.field ?? nested.field;
  const internal = isInternal(observable.internal ?? nested.internal);

  const fields = [
    ...(Array.isArray(observable.fields) ? observable.fields : []),
    ...(Array.isArray(nested.fields) ? nested.fields : []),
    field,
  ].filter(
    (candidate) =>
      typeof candidate === 'string' && candidate.trim() !== ''
  );

  if (type === 'hash') {
    value = value
      .replace(/^(?:MD5|SHA-?1|SHA-?256|SHA-?512)\s*=\s*/i, '')
      .replace(/\s+/g, '')
      .toLowerCase();
  } else if (type === 'ip') {
    value = value.toLowerCase();
  } else if (type === 'domain') {
    value = value.replace(/\.$/, '').toLowerCase();
  }

  const normalizedJson = {
    ...observable,
    type,
    value,
    field,
    internal,
    fields: [...new Set(fields.map((candidate) => candidate.trim()))],
  };

  if (!type || !value) {
    output.push({ ...item, json: normalizedJson });
    continue;
  }

  const key = `${type}:${value}`;

  if (!seen.has(key)) {
    const normalizedItem = { ...item, json: normalizedJson };
    seen.set(key, normalizedItem);
    output.push(normalizedItem);
    continue;
  }

  const existing = seen.get(key);

  existing.json.internal =
    isInternal(existing.json.internal) || internal;

  existing.json.fields = [
    ...new Set([
      ...(existing.json.fields ?? []),
      ...normalizedJson.fields,
    ]),
  ];
}

return output;
