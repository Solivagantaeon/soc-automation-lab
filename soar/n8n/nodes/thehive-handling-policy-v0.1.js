/**
 * SOC n8n handling policy for TheHive and external enrichment.
 *
 * Place on the non-closed route after `Decision`/`Route to TheHive?` and before
 * `Build TheHive Alert`. This node assigns TheHive markings only.
 * The exact `soc-lab-test` Wazuh rule group identifies synthetic lab traffic.
 * Other alerts default to TLP:AMBER and PAP:AMBER until an upstream marking
 * says otherwise.
 *
 * TLP controls disclosure; PAP controls permitted use/actions. Neither is
 * inferred from alert severity or from the other marking.
 */

const items = $input.all();

let webhookEvent = {};
try {
  const webhookOutput = $('Webhook').first().json ?? {};
  let body = webhookOutput.body ?? webhookOutput;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  if (Array.isArray(body)) body = body[0] ?? {};
  webhookEvent = body && typeof body === 'object' ? body : {};
} catch {
  webhookEvent = {};
}

const TLP = { CLEAR: 0, GREEN: 1, AMBER: 2, AMBER_STRICT: 3, RED: 4 };
const PAP = { CLEAR: 0, GREEN: 1, AMBER: 2, RED: 3 };

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeLabel(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/^tlp\s*:?\s*/, '')
    .replace(/^pap\s*:?\s*/, '')
    .replace(/[\s_-]+/g, '');
}

function parseTlp(value) {
  if (Number.isInteger(value) && value >= 0 && value <= 4) return value;
  const label = normalizeLabel(value);
  const values = {
    clear: TLP.CLEAR,
    white: TLP.CLEAR,
    '0': TLP.CLEAR,
    green: TLP.GREEN,
    '1': TLP.GREEN,
    amber: TLP.AMBER,
    '2': TLP.AMBER,
    'amber+strict': TLP.AMBER_STRICT,
    amberstrict: TLP.AMBER_STRICT,
    '3': TLP.AMBER_STRICT,
    red: TLP.RED,
    '4': TLP.RED,
  };
  return Object.prototype.hasOwnProperty.call(values, label) ? values[label] : null;
}

function parsePap(value) {
  if (Number.isInteger(value) && value >= 0 && value <= 3) return value;
  const label = normalizeLabel(value);
  const values = {
    clear: PAP.CLEAR,
    white: PAP.CLEAR,
    '0': PAP.CLEAR,
    green: PAP.GREEN,
    '1': PAP.GREEN,
    amber: PAP.AMBER,
    '2': PAP.AMBER,
    red: PAP.RED,
    '3': PAP.RED,
  };
  return Object.prototype.hasOwnProperty.call(values, label) ? values[label] : null;
}

function collectMarkings(root, kind, sourceEvent) {
  const alert = root.alert ?? root;
  const sourceAlert = sourceEvent.alert ?? sourceEvent;
  const observables = asArray(alert.observables ?? root.observables);
  const values = [
    root[kind],
    root.markings?.[kind],
    root.handling_policy?.[kind],
    root.thehive_policy?.[kind],
    alert[kind],
    alert.markings?.[kind],
    alert.handling_policy?.[kind],
    alert.thehive_policy?.[kind],
    alert.data?.[kind],
    sourceEvent[kind],
    sourceEvent.markings?.[kind],
    sourceEvent.data?.[kind],
    sourceAlert[kind],
    sourceAlert.markings?.[kind],
    ...observables.flatMap(observable => [
      observable[kind],
      observable.markings?.[kind],
    ]),
  ];

  const tagCollections = [
    root.tags,
    alert.tags,
    sourceEvent.tags,
    sourceAlert.tags,
    ...observables.map(observable => observable.tags),
  ];
  for (const tags of tagCollections) {
    for (const tag of asArray(tags)) {
      const text = String(tag ?? '').trim();
      const match = new RegExp(`^${kind}\\s*:\\s*(.+)$`, 'i').exec(text);
      if (match) values.push(match[1]);
    }
  }

  const parsed = values.map(kind === 'tlp' ? parseTlp : parsePap).filter(Number.isInteger);
  // The most restrictive explicit marking applies to the whole alert.
  return parsed.length > 0 ? Math.max(...parsed) : null;
}

function getRuleGroups(root, sourceEvent) {
  const alert = root.alert ?? root;
  const sourceAlert = sourceEvent.alert ?? sourceEvent;
  const groups = [
    ...asArray(alert.rule?.groups),
    ...asArray(root.rule?.groups),
    ...asArray(alert.groups),
    ...asArray(root.groups),
    ...asArray(sourceAlert.rule?.groups),
    ...asArray(sourceEvent.rule?.groups),
    ...asArray(sourceAlert.groups),
    ...asArray(sourceEvent.groups),
  ];
  return [...new Set(groups.map(value => String(value).trim().toLowerCase()).filter(Boolean))];
}

function tlpLabel(value) {
  return ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'][value];
}

function papLabel(value) {
  return ['CLEAR', 'GREEN', 'AMBER', 'RED'][value];
}

return items.map(itemData => {
  const root = itemData.json ?? {};
  const groups = getRuleGroups(root, webhookEvent);
  const syntheticLab = groups.includes('soc-lab-test');

  const explicitTlp = collectMarkings(root, 'tlp', webhookEvent);
  const explicitPap = collectMarkings(root, 'pap', webhookEvent);
  const tlp = explicitTlp ?? (syntheticLab ? TLP.CLEAR : TLP.AMBER);
  // This workflow performs passive online reputation lookups, so AMBER is the
  // default PAP. This late node records PAP:RED in TheHive but cannot block
  // Cortex lookups that already ran earlier in this execution.
  const pap = explicitPap ?? PAP.AMBER;

  const reasons = [];
  reasons.push(explicitTlp === null
    ? syntheticLab
      ? 'No source TLP was supplied; exact soc-lab-test group uses TLP:CLEAR for synthetic data.'
      : 'No source TLP was supplied; client or unclassified data defaults to TLP:AMBER.'
    : `Inherited the most restrictive explicit TLP marking (${tlpLabel(tlp)}).`);
  reasons.push(explicitPap === null
    ? 'No source PAP was supplied. PAP:AMBER default applied. Confirm it against the data-sharing policy.'
    : `Inherited the most restrictive explicit PAP marking (${papLabel(pap)}).`);
  reasons.push('This node runs after enrichment and applies TheHive markings; it cannot block Cortex requests already completed in this execution.');

  return {
    json: {
      ...root,
      thehive_policy: {
        version: '0.1',
        context: syntheticLab ? 'synthetic_lab' : 'client_or_unclassified',
        tlp,
        tlp_label: tlpLabel(tlp),
        pap,
        pap_label: papLabel(pap),
        application_stage: 'post_decision',
        enrichment_gate_enforced: false,
        reasons,
      },
    },
  };
});
