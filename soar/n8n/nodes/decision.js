/**
 * SOC n8n Decision stage
 * Input: rows returned by Lookup Asset
 * Reads the scoring result from the node named "Scoring".
 *
 * Outcomes:
 * - closed
 * - analyst_review
 * - malicious
 */

const lookupItems = $input.all().map(item => item.json ?? {});

let scored = {};
try {
  scored = $('Scoring').first().json ?? {};
} catch {
  scored = {};
}

const alert = scored.alert ?? {};
const agent = alert.agent ?? {};
const scoring = scored.scoring ?? {};
const processing = scored.processing ?? {};

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function isTrue(value) {
  return value === true || value === 1 || String(value).toLowerCase() === 'true';
}

function normalizedName(value) {
  return String(value ?? '').trim().toLowerCase();
}

const matchingAssets = lookupItems.filter(row =>
  row.agent_id !== undefined &&
  row.agent_name !== undefined &&
  String(row.agent_id) === String(agent.id ?? '') &&
  normalizedName(row.agent_name) === normalizedName(agent.name)
);

const asset = matchingAssets.length === 1 ? matchingAssets[0] : null;

const indicators = asArray(scored.misp?.unique_indicators);
const attributes = indicators.flatMap(indicator =>
  asArray(indicator.attributes)
);
const mispTags = new Set(
  attributes
    .flatMap(attribute => asArray(attribute.tags))
    .map(tag => String(tag).toLowerCase())
);

const hasMaliciousMispTag = mispTags.has('soc-lab:malicious');
const hasBenignMispTag = mispTags.has('soc-lab:benign');
const cortexResults = asArray(scored.cortex?.results);

function taxonomyValue(result, predicate) {
  const taxonomies = asArray(result.summary?.taxonomies);
  const found = taxonomies.find(item =>
    String(item.predicate ?? '').toLowerCase() === predicate.toLowerCase()
  );
  return found?.value;
}

const maliciousSignals = [];

if (hasMaliciousMispTag) {
  maliciousSignals.push('MISP tag: soc-lab:malicious');
}

const maltiverseMalicious = cortexResults.some(result =>
  result.status === 'complete' &&
  /maltiverse/i.test(String(result.analyzer ?? '')) &&
  String(result.summary?.classification ?? '').toLowerCase() === 'malicious'
);
if (maltiverseMalicious) maliciousSignals.push('Maltiverse classification: malicious');

const strongMhrDetection = cortexResults.some(result => {
  if (result.status !== 'complete' || !/teamcymru/i.test(String(result.analyzer ?? ''))) return false;
  const detection = Number(taxonomyValue(result, 'detection_pct'));
  return Number.isFinite(detection) && detection >= 50;
});
if (strongMhrDetection) maliciousSignals.push('Team Cymru MHR detection is at least 50%');

const strongVirusTotalDetection = cortexResults.some(result => {
  if (result.status !== 'complete' || !/virustotal/i.test(String(result.analyzer ?? ''))) return false;
  const value = String(taxonomyValue(result, 'GetReport') ?? '');
  const match = /^(\d+)\s*\/\s*(\d+)$/.exec(value);
  return Boolean(match) && Number(match[1]) >= 10;
});
if (strongVirusTotalDetection) maliciousSignals.push('VirusTotal reports at least 10 detections');

const score = Number(scoring.score);
const coverage = Number(scoring.coverage);
const verdict = String(scoring.verdict ?? '');
const validScoring = Number.isFinite(score) && Number.isFinite(coverage) && verdict.length > 0;

const observableTypes = new Set(['ip', 'domain', 'url', 'hash']);
const hasEligibleObservable = asArray(alert.observables).some(observable => {
  const type = String(observable.type ?? '').toLowerCase();
  const internal = isTrue(observable.internal);
  return observable.value !== undefined &&
    observable.value !== null &&
    String(observable.value) !== '' &&
    observableTypes.has(type) &&
    !internal;
});

const failed = asArray(processing.failed);
const pending = asArray(processing.pending);
const sourceState = scoring.sources ?? {};
const partialSources = asArray(sourceState.partial);
const failedSources = asArray(sourceState.failed);
const inputProblems = asArray(scoring.input_problems);
const configWarnings = asArray(scoring.config_warnings);
const breakdown = asArray(scoring.breakdown);

const unclearVirusTotalResult = breakdown.some(item =>
  item.source === 'virustotal' &&
  /no parsable result/i.test(String(item.reason ?? ''))
);

const analysisComplete =
  validScoring &&
  processing.status === 'complete' &&
  coverage === 1 &&
  failed.length === 0 &&
  pending.length === 0 &&
  partialSources.length === 0 &&
  failedSources.length === 0 &&
  inputProblems.length === 0 &&
  configWarnings.length === 0 &&
  !unclearVirusTotalResult;

const conflict =
  hasBenignMispTag &&
  (maliciousSignals.length > 0 || (validScoring && score >= 40));

const assetAllowed = isTrue(asset?.auto_close_allowed);
const assetIsCritical = String(asset?.criticality ?? '').toLowerCase() === 'critical';

let outcome = 'analyst_review';
let reasonCode = 'default_review';
const reasons = [];

if (!validScoring) {
  reasonCode = 'missing_scoring_data';
  reasons.push('Scoring data is missing or invalid.');
} else if (!hasEligibleObservable) {
  reasonCode = 'no_eligible_observable';
  reasons.push('No eligible external observable was found.');
} else if (conflict) {
  reasonCode = 'conflicting_evidence';
  reasons.push('Benign and malicious or elevated-risk evidence conflict.');
} else if (!analysisComplete) {
  reasonCode = 'incomplete_analysis';
  reasons.push('Enrichment is incomplete, unavailable, or has an unclear result.');
} else if (maliciousSignals.length > 0) {
  outcome = 'malicious';
  reasonCode = 'malicious_evidence';
  reasons.push(...maliciousSignals);
} else if (verdict === 'high') {
  outcome = 'malicious';
  reasonCode = 'high_scoring_verdict';
  reasons.push('The complete analysis produced a high scoring verdict. This is automated routing, not analyst confirmation.');
} else if (verdict === 'likely_false_positive') {
  if (matchingAssets.length !== 1) {
    reasonCode = 'asset_not_found_or_ambiguous';
    reasons.push('The agent has no single exact match in the asset inventory.');
  } else if (assetIsCritical) {
    reasonCode = 'critical_asset';
    reasons.push('Critical assets are not eligible for automatic closure.');
  } else if (!assetAllowed) {
    reasonCode = 'asset_not_allowlisted';
    reasons.push('The asset inventory does not allow automatic closure for this agent.');
  } else {
    outcome = 'closed';
    reasonCode = 'complete_low_risk_analysis';
    reasons.push('The complete analysis produced a likely-false-positive verdict and the asset inventory allows automatic closure.');
  }
} else {
  reasonCode = 'analyst_review_required';
  reasons.push('Scoring verdict "' + verdict + '" requires analyst review.');
}

return [{
  json: {
    ...scored,
    asset_inventory: {
      lookup_status: matchingAssets.length === 1 ? 'matched' : matchingAssets.length > 1 ? 'ambiguous' : 'not_found',
      agent_id: asset?.agent_id ?? agent.id ?? null,
      agent_name: asset?.agent_name ?? agent.name ?? null,
      asset_type: asset?.asset_type ?? 'unknown',
      criticality: asset?.criticality ?? 'unknown',
      auto_close_allowed: assetAllowed,
      reason: asset?.reason ?? null,
      last_reviewed: asset?.last_reviewed ?? null,
    },
    decision: {
      policy_version: '0.1',
      outcome,
      reason_code: reasonCode,
      reasons,
      score: validScoring ? score : null,
      verdict: verdict || 'unknown',
      coverage: Number.isFinite(coverage) ? coverage : null,
      analysis_complete: analysisComplete,
      malicious_signals: maliciousSignals,
      has_benign_misp_tag: hasBenignMispTag,
    },
  },
}];