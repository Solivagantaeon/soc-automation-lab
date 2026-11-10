/**
 * SOC n8n TheHive alert builder
 * Input: output from the Decision node for analyst_review or malicious.
 * Reads the detailed normalized event from "Normalize Alert" and the
 * handling policy from "Apply TheHive Handling Policy".
 * Output: top-level TheHive alert fields for the native node's auto-map mode,
 * plus `thehive_observables` for a separate Observable -> Create node.
 *
 * Closed decisions must bypass this node and the TheHive HTTP Request node.
 */

const items = $input.all();

let normalized = {};
try {
  normalized = $('Normalize Alert').first().json ?? {};
} catch {
  normalized = {};
}

let handlingPolicyFromNode = {};
try {
  handlingPolicyFromNode = $('Apply TheHive Handling Policy').first().json?.thehive_policy ?? {};
} catch {
  handlingPolicyFromNode = {};
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function text(value, fallback = 'Not provided') {
  if (value === undefined || value === null || String(value).trim() === '') {
    return fallback;
  }
  return String(value).trim();
}

function isTrue(value) {
  return value === true || value === 1 || String(value).toLowerCase() === 'true';
}

function normalizedValue(value) {
  return String(value ?? '').trim().toLowerCase();
}

function safeJson(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function truncate(value, max = 500) {
  const result = String(value ?? '');
  return result.length > max ? result.slice(0, max) + '…' : result;
}

function dateText(value) {
  if (value === undefined || value === null || value === '') return 'Not available';
  const parsed = typeof value === 'number' ? value : Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : 'Not available';
}

function formatSummary(summary) {
  if (!summary || typeof summary !== 'object') return 'No report summary returned';

  const entries = Object.entries(summary).map(([key, value]) => {
    if (Array.isArray(value)) {
      const compact = value.map(item => {
        if (item && typeof item === 'object') {
          const label = item.predicate ?? item.name ?? item.type ?? 'item';
          const detail = item.value ?? item.count ?? item.description ?? item;
          return `${label}=${safeJson(detail)}`;
        }
        return String(item);
      }).join(', ');
      return `${key}: ${compact || 'none'}`;
    }
    if (value && typeof value === 'object') return `${key}: ${safeJson(value)}`;
    return `${key}: ${String(value)}`;
  });

  return truncate(entries.join('; ') || 'No report summary returned', 900);
}

function taxonomyValue(result, predicate) {
  const taxonomies = asArray(result.summary?.taxonomies);
  const match = taxonomies.find(item =>
    String(item.predicate ?? '').toLowerCase() === predicate.toLowerCase()
  );
  return match?.value;
}

function isStrongVirusTotalDetection(result) {
  const raw = String(taxonomyValue(result, 'GetReport') ?? '');
  const match = /^(\d+)\s*\/\s*(\d+)$/.exec(raw);
  return Boolean(match) && Number(match[1]) >= 10;
}

function observableEvidence(value, mispIndicators, cortexResults) {
  const key = normalizedValue(value);
  const matchingIndicators = mispIndicators.filter(indicator =>
    normalizedValue(indicator.value) === key
  );
  const attributes = matchingIndicators.flatMap(indicator => asArray(indicator.attributes));
  const tags = new Set(attributes.flatMap(attribute =>
    asArray(attribute.tags).map(tag => String(tag).toLowerCase())
  ));

  const malicious = [];
  const benign = [];

  if (tags.has('soc-lab:malicious')) malicious.push('MISP tag soc-lab:malicious');
  if (tags.has('soc-lab:benign')) benign.push('MISP tag soc-lab:benign');

  for (const result of cortexResults) {
    if (normalizedValue(result.observable) !== key || result.status !== 'complete') continue;

    const analyzer = String(result.analyzer ?? '').toLowerCase();
    const summary = result.summary ?? {};
    const classification = String(summary.classification ?? '').toLowerCase();

    if (analyzer.includes('maltiverse')) {
      if (classification === 'malicious') malicious.push('Maltiverse classification malicious');
      if (classification === 'whitelist' || classification === 'benign') {
        benign.push(`Maltiverse classification ${classification}`);
      }
    }

    if (analyzer.includes('abuseipdb') && summary.whitelisted === true) {
      benign.push('AbuseIPDB marked the IP as whitelisted');
    }

    if (analyzer.includes('teamcymru')) {
      const detection = Number(taxonomyValue(result, 'detection_pct'));
      if (Number.isFinite(detection) && detection >= 50) {
        malicious.push(`Team Cymru MHR detection ${detection}%`);
      }
    }

    if (analyzer.includes('virustotal') && isStrongVirusTotalDetection(result)) {
      malicious.push(`VirusTotal ${taxonomyValue(result, 'GetReport')} detections`);
    }
  }

  let verdict = 'unknown';
  if (malicious.length > 0 && benign.length === 0) verdict = 'malicious';
  if (benign.length > 0 && malicious.length === 0) verdict = 'benign';

  const allEvidence = [...malicious, ...benign];
  const note = allEvidence.length > 0
    ? allEvidence.join('; ')
    : 'No decisive source verdict; treat as unknown';

  return { verdict, note };
}

function toTheHiveObservable(observable, mispIndicators, cortexResults, tlp, pap) {
  const type = String(observable.type ?? observable.dataType ?? '').toLowerCase();
  const value = text(observable.value ?? observable.data, '');
  const supportedTypes = new Set(['ip', 'domain', 'url', 'hash']);
  if (!value || !supportedTypes.has(type) || isTrue(observable.internal)) return null;

  const evidence = observableEvidence(value, mispIndicators, cortexResults);
  const message = [
    `Source field: ${text(observable.field, 'Not recorded')}`,
    `IOC verdict: ${evidence.verdict}`,
    `Evidence: ${evidence.note}`,
  ].join('\n');

  return {
    dataType: type,
    data: value,
    message,
    tags: [`ioc-verdict:${evidence.verdict}`],
    tlp,
    pap,
    ioc: true,
  };
}

function classifySeverity(outcome, decision, asset) {
  const verdict = String(decision.verdict ?? '').toLowerCase();
  const score = Number(decision.score);
  const criticalAsset = String(asset.criticality ?? '').toLowerCase() === 'critical';
  const complete = decision.analysis_complete === true;

  if (outcome === 'malicious') {
    if (criticalAsset) {
      return { value: 4, label: 'CRITICAL', reason: 'Malicious outcome affects an asset marked critical.' };
    }
    if (complete && Number.isFinite(score) && score >= 90) {
      return { value: 4, label: 'CRITICAL', reason: 'Complete analysis produced a malicious outcome with score 90 or higher.' };
    }
    return { value: 3, label: 'HIGH', reason: 'Decision classified the alert as malicious.' };
  }

  if (criticalAsset) {
    return { value: 3, label: 'HIGH', reason: 'The affected asset is marked critical and the alert requires analyst review.' };
  }
  if (!complete || !Number.isFinite(score)) {
    return { value: 2, label: 'MEDIUM', reason: 'Analysis is incomplete or the score is unavailable; keep the alert for analyst review.' };
  }
  if (verdict === 'high' || score >= 70) {
    return { value: 3, label: 'HIGH', reason: 'Complete analysis produced a high verdict or score of 70 or higher.' };
  }
  if (verdict === 'medium' || score >= 40) {
    return { value: 2, label: 'MEDIUM', reason: 'Complete analysis produced a medium verdict or score from 40 to 69.' };
  }
  if ((verdict === 'low' || verdict === 'likely_false_positive') && score < 40) {
    return { value: 1, label: 'LOW', reason: 'Complete low-risk analysis produced a low or likely-false-positive verdict below 40.' };
  }
  return { value: 2, label: 'MEDIUM', reason: 'The decision does not match a defined low, medium, or high severity rule.' };
}

function buildDescription(item, normalizedAlert, outcome, tlp, pap, observables, policy, severityInfo) {
  const alert = item.alert ?? {};
  const decision = item.decision ?? {};
  const scoring = item.scoring ?? {};
  const processing = item.processing ?? {};
  const asset = item.asset_inventory ?? {};
  const rule = normalizedAlert.rule ?? alert.rule ?? {};
  const agent = normalizedAlert.agent ?? alert.agent ?? {};
  const userValues = asArray(normalizedAlert.observables)
    .filter(observable => observable.kind === 'user')
    .map(observable => observable.data ?? observable.value)
    .filter(Boolean);
  const cortexResults = asArray(item.cortex?.results);
  const mispIndicators = asArray(item.misp?.unique_indicators);
  const mitreIds = asArray(rule.mitre_ids ?? alert.mitre?.ids);
  const mitreTactics = asArray(rule.mitre_tactics ?? alert.mitre?.tactics);
  const mitreTechniques = asArray(rule.mitre_techniques ?? alert.mitre?.techniques);
  const failed = asArray(processing.failed);
  const pending = asArray(processing.pending);
  let dedup = {};
  try {
    dedup = $('Dedup').first().json ?? {};
  } catch {
    dedup = {};
  }
  const firstSeen = alert.timestamp ?? normalizedAlert.timestamp;
  const lastSeen = alert.timestamp ?? normalizedAlert.timestamp;
  const duplicateCount = Number(dedup.duplicate_count);
  const relatedAlertCount = Number.isInteger(duplicateCount) && duplicateCount > 0
    ? duplicateCount
    : 1;

  const nextStep = outcome === 'malicious'
    ? 'Review the listed evidence and affected host, then determine containment or escalation under the SOC response procedure. This is an automated classification, not analyst confirmation.'
    : decision.analysis_complete !== true
      ? 'Review the failed or pending sources before treating any observable as benign. Use the evidence recorded here to continue analyst triage.'
      : String(asset.criticality ?? '').toLowerCase() === 'critical'
        ? 'Prioritize this critical asset. Automatic closure is blocked for this asset.'
        : 'Review the scoring result and source evidence, then record the analyst decision in TheHive.';

  const lines = [
    'SOC AUTOMATED TRIAGE — WAZUH → N8N → THEHIVE',
    '',
    '[AUTOMATED DECISION]',
    `Outcome: ${text(outcome)}`,
    `TheHive severity: ${severityInfo.label} (${severityInfo.value})`,
    `Severity rationale: ${severityInfo.reason}`,
    `Reason code: ${text(decision.reason_code)}`,
    `Reason: ${asArray(decision.reasons).map(String).join('; ') || 'Not provided'}`,
    `Score: ${text(decision.score ?? scoring.score, 'Unknown')}`,
    `Verdict: ${text(decision.verdict ?? scoring.verdict, 'Unknown')}`,
    `Coverage: ${text(decision.coverage ?? scoring.coverage, 'Unknown')}`,
    `Analysis complete: ${decision.analysis_complete === true ? 'yes' : 'no'}`,
    `Recommended next step: ${nextStep}`,
    '',
    '[ASSET]',
    `Host: ${text(agent.name)}`,
    `Agent ID: ${text(agent.id)}`,
    `Agent IP: ${text(agent.ip)}`,
    `Asset type: ${text(asset.asset_type, 'Unknown')}`,
    `Criticality: ${text(asset.criticality, 'Unknown')}`,
    `Auto-close allowed: ${asset.auto_close_allowed === true ? 'yes' : 'no'}`,
    `Inventory reason: ${text(asset.reason)}`,
    `User: ${userValues.length > 0 ? [...new Set(userValues.map(String))].join(', ') : 'Not present in the normalized event'}`,
    '',
    '[SOURCE ALERT]',
    `Source: Wazuh (${text(alert.source_format ?? normalizedAlert.source_format)})`,
    `Source alert ID: ${text(alert.id ?? alert.alert_id ?? normalizedAlert.alert_id)}`,
    `Timestamp: ${text(alert.timestamp ?? normalizedAlert.timestamp)}`,
    `Manager: ${text(alert.manager ?? normalizedAlert.manager)}`,
    `Rule ID: ${text(rule.id)}`,
    `Wazuh rule level: ${text(rule.level, 'Unknown')}`,
    `Rule description: ${text(rule.description)}`,
    `First seen: ${dateText(firstSeen)}`,
    `Last seen: ${dateText(lastSeen)}`,
    `Alert count in the current Dedup window: ${relatedAlertCount}`,
    `Rule groups: ${asArray(rule.groups).join(', ') || 'Not provided'}`,
    `Wazuh firedtimes: ${text(rule.firedtimes, 'Not provided; this is not a correlated-alert count')}`,
    `Location: ${text(normalizedAlert.location)}`,
    `Decoder: ${text(normalizedAlert.decoder)}`,
    `Signature: ${text(normalizedAlert.signature)}`,
    `Command line: ${text(normalizedAlert.command_line)}`,
    `File path: ${text(normalizedAlert.syscheck?.path)}`,
    `MITRE ATT&CK IDs: ${mitreIds.join(', ') || 'None recorded'}`,
    `MITRE tactics: ${mitreTactics.join(', ') || 'None recorded'}`,
    `MITRE techniques: ${mitreTechniques.join(', ') || 'None recorded'}`,
    '',
    '[OBSERVABLES]',
    ...(observables.length > 0
      ? observables.map(observable =>
          `${observable.dataType}: ${observable.data} — ${observable.tags[0].replace('ioc-verdict:', '')}; ${observable.message.split('\n').slice(1).join('; ')}`
        )
      : ['No eligible external IP, domain, URL, or hash was present.']),
    '',
    '[MISP REFERENCES]',
    ...(mispIndicators.length > 0
      ? mispIndicators.flatMap(indicator => {
          const attrs = asArray(indicator.attributes);
          return attrs.map(attribute => {
            const event = attribute.event ?? {};
            return `${text(indicator.type, 'IOC')} ${text(indicator.value)} — event ${text(event.id, 'ID unavailable')} (${text(event.title, 'title unavailable')}); to_ids=${text(attribute.to_ids, 'unknown')}; tags=${asArray(attribute.tags).join(', ') || 'none'}; comment=${text(attribute.comment, 'none')}`;
          });
        })
      : ['No matching MISP attributes.']),
    '',
    '[CORTEX RESULTS]',
    ...(cortexResults.length > 0
      ? cortexResults.map(result =>
          `${text(result.analyzer)} for ${text(result.observable)} [${text(result.status)}]: ${formatSummary(result.summary)}`
        )
      : ['No Cortex results recorded.']),
    '',
    '[UNAVAILABLE OR PENDING SOURCES]',
    ...(failed.length > 0
      ? failed.map(entry =>
          `Failed: ${text(entry.service ?? entry.analyzer)}; observable=${text(entry.observable)}; node=${text(entry.node)}; error=${truncate(text(entry.error, entry.status ?? 'No error detail'), 300)}`
        )
      : ['Failed: none']),
    ...(pending.length > 0
      ? pending.map(entry => `Pending: ${text(entry.analyzer)}; observable=${text(entry.observable)}`)
      : ['Pending: none']),
    '',
    `[THEHIVE MARKINGS] TLP=${tlp}; PAP=${pap}`,
    `[HANDLING POLICY] Context=${text(policy.context, 'unspecified')}; applied at=${text(policy.application_stage, 'unspecified')}; earlier Cortex gate enforced=${policy.enrichment_gate_enforced === true ? 'yes' : 'no'}`,
    ...asArray(policy.reasons).map(reason => `Policy: ${text(reason)}`),
  ];

  return lines.join('\n');
}

return items.map(itemData => {
  const item = itemData.json ?? {};
  const decision = item.decision ?? {};
  const outcome = String(decision.outcome ?? '');

  if (!['analyst_review', 'malicious'].includes(outcome)) {
    throw new Error(`Build TheHive Alert only accepts analyst_review or malicious; received "${outcome || 'missing'}".`);
  }

  const alert = item.alert ?? {};
  const rule = normalized.rule ?? alert.rule ?? {};
  const agent = normalized.agent ?? alert.agent ?? {};
  const sourceRef = text(alert.id ?? alert.alert_id ?? normalized.alert_id, '');

  if (!sourceRef) throw new Error('Cannot create TheHive alert: Wazuh source alert ID is missing.');
  if (sourceRef.length > 128) throw new Error('Cannot create TheHive alert: sourceRef exceeds TheHive’s 128-character limit.');

  // Read the pre-enrichment policy by node name. This remains authoritative
  // even if downstream Merge nodes drop the policy object from their items.
  const policy = Number.isInteger(Number(handlingPolicyFromNode.tlp))
    ? handlingPolicyFromNode
    : item.thehive_policy ?? {};
  const tlpValue = Number(policy.tlp);
  const papValue = Number(policy.pap);
  if (!Number.isInteger(tlpValue) || tlpValue < 0 || tlpValue > 4) {
    throw new Error(`Missing or invalid TheHive TLP from Apply TheHive Handling Policy: ${policy.tlp}`);
  }
  if (!Number.isInteger(papValue) || papValue < 0 || papValue > 3) {
    throw new Error(`Missing or invalid TheHive PAP from Apply TheHive Handling Policy: ${policy.pap}`);
  }
  const tlp = tlpValue;
  const pap = papValue;
  const mispIndicators = asArray(item.misp?.unique_indicators);
  const cortexResults = asArray(item.cortex?.results);
  const sourceObservables = asArray(alert.observables).length > 0
    ? alert.observables
    : asArray(normalized.observables);

  const unique = new Map();
  for (const observable of sourceObservables) {
    const thehiveObservable = toTheHiveObservable(observable, mispIndicators, cortexResults, tlp, pap);
    if (!thehiveObservable) continue;
    const key = `${thehiveObservable.dataType}\u0000${normalizedValue(thehiveObservable.data)}`;
    if (!unique.has(key)) unique.set(key, thehiveObservable);
  }
  const observables = [...unique.values()];

  const asset = item.asset_inventory ?? {};
  const score = decision.score ?? item.scoring?.score;
  const verdict = text(decision.verdict ?? item.scoring?.verdict, 'unknown');
  const host = text(agent.name, 'unknown-host');
  const sourceIp = text(normalized.source_ip, '');
  const sampleIoc = observables.find(observable => observable.dataType === 'ip')?.data;
  const subject = text(rule.description, 'Wazuh alert');
  const lead = outcome === 'malicious' ? 'Malicious evidence' : 'Analyst review';
  const location = sourceIp
    ? ` from ${sourceIp}`
    : sampleIoc
      ? ` (IOC ${sampleIoc})`
      : '';
  const title = truncate(`${lead} on ${host}${location}: ${subject}`, 512);
  const tags = [
    'auto-triage',
    'source:wazuh',
    `decision:${outcome}`,
    `verdict:${String(verdict).toLowerCase().replace(/[^a-z0-9_-]/g, '_')}`,
    `severity:${classifySeverity(outcome, decision, asset).label.toLowerCase()}`,
    decision.analysis_complete === true ? 'analysis:complete' : 'incomplete-analysis',
  ];
  if (String(asset.criticality ?? '').toLowerCase() === 'critical') tags.push('asset:critical');

  const timestamp = alert.timestamp ?? normalized.timestamp;
  const parsedDate = timestamp ? Date.parse(timestamp) : NaN;
  const severityInfo = classifySeverity(outcome, decision, asset);
  const description = buildDescription(item, normalized, outcome, tlp, pap, observables, policy, severityInfo);
  const summary = truncate(
    `${outcome}; ${text(decision.reason_code)}; score=${text(score, 'unknown')}; verdict=${verdict}; analysis_complete=${decision.analysis_complete === true}`,
    1000
  );

  const thehiveFields = {
    type: 'external',
    source: 'Wazuh',
    sourceRef,
    title,
    summary,
    description,
    severity: severityInfo.value,
    tlp,
    pap,
    tags: [...new Set(tags)],
    follow: false,
    flag: outcome === 'malicious',
  };
  if (Number.isFinite(parsedDate)) thehiveFields.date = new Date(parsedDate).toISOString();

  return {
    json: {
      ...item,
      ...thehiveFields,
      // Keep these out of the Alert node's static Observables collection.
      // The native Observable/Create node will add one item at a time after
      // the alert exists, preserving every supported IOC and its own evidence.
      thehive_observables: observables,
    },
  };
});
