/**
 * SOC - Alert Scoring
 * Stage: Scoring (after "Summary Enrichments", before "Create an alert")
 * Version: 0.2.2
 *
 * Input:  output of Summary Enrichments (alert, misp, cortex, processing)
 *         optionally with a "scoring_config" field added by an upstream
 *         "Scoring Config" node (Edit Fields / Set node)
 * Output: the same object (without scoring_config) plus a "scoring" field
 *
 * n8n Code node:
 * Mode: Run Once for All Items
 *
 * Principles:
 * - all weights and switches live in the config (DEFAULT_CONFIG below is
 *   the fallback; the upstream node overrides any part of it)
 * - the config is validated: wrong types, unknown keys and inconsistent
 *   bands are reported in scoring.config_warnings and defaults are used
 * - each source contributes one entry (the max over all observables)
 * - missing data (error/pending) is NOT treated as "clean":
 *   it lowers "coverage", and low coverage blocks a false-positive verdict
 * - a disabled source is ignored completely (points and coverage)
 * - an item without the expected enrichment data is never scored as clean:
 *   its verdict is needs_review and input_problems explains why
 * - CIRCL "known" cancels a hash's weak Team Cymru MHR detections and adds
 *   the known-good discount, but a strong MHR detection overrides CIRCL
 */

const DEFAULT_CONFIG = {
  version: '0.2',

  rule_level_multiplier: 2, // Wazuh rule level 0-15 -> 0-30 points

  // below this coverage, a low score is not accepted as a false positive
  min_coverage_for_fp: 0.6,

  // score thresholds for the verdict (high > medium > low)
  bands: { high: 70, medium: 40, low: 20 },

  sources: {
    misp: { enabled: true, to_ids: 30, match: 15 },

    abuseipdb: {
      enabled: true,
      whitelisted: -10,
      tiers: [
        { min: 75, points: 25 },
        { min: 25, points: 12 },
      ],
    },

    maltiverse: {
      enabled: true,
      malicious: 20,
      suspicious: 10,
      historical_only: 5, // historical matches exist, but classification is not malicious
      whitelist: -5,
    },

    virustotal: {
      enabled: true,
      tiers: [
        { min: 10, points: 25 },
        { min: 3, points: 15 },
        { min: 1, points: 8 },
      ],
    },

    teamcymru: {
      enabled: true,
      // MHR detections of a hash known in CIRCL are ignored, unless the
      // detection is strong (see sources.circl.known_good_unless_mhr_pct)
      ignore_when_circl_known: true,
      tiers: [
        { min: 50, points: 15 },
        { min: 20, points: 8 },
      ],
    },

    circl: {
      enabled: true,
      known_good: -10,
      // a CIRCL-known hash keeps its known-good status only while its MHR
      // detection is below this percentage (a value above 100 turns the
      // exception off)
      known_good_unless_mhr_pct: 50,
    },
  },
};

// ------------------------------------------------------------
// Config loading and validation
// ------------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validTiers(value) {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.every(t =>
      isPlainObject(t) &&
      Number.isFinite(Number(t.min)) &&
      Number.isFinite(Number(t.points))
    );
}

// Merges "override" over "defaults". Every key is checked against the
// type of its default; invalid values keep the default and add a warning.
function mergeConfig(defaults, override, path, warnings) {
  const out = {};
  const prefix = path ? `${path}.` : '';

  for (const key of Object.keys(defaults)) {
    const def = defaults[key];
    const where = `${prefix}${key}`;

    const provided =
      isPlainObject(override) &&
      Object.prototype.hasOwnProperty.call(override, key);

    if (!provided) {
      out[key] = def;
      continue;
    }

    const val = override[key];

    if (isPlainObject(def)) {
      if (isPlainObject(val)) {
        out[key] = mergeConfig(def, val, where, warnings);
      } else {
        warnings.push(`${where}: expected an object, default used`);
        out[key] = def;
      }
    } else if (Array.isArray(def)) {
      if (validTiers(val)) {
        out[key] = val.map(t => ({
          min: Number(t.min),
          points: Number(t.points),
        }));
      } else {
        warnings.push(`${where}: expected a non-empty list of {min, points}, default used`);
        out[key] = def;
      }
    } else if (typeof def === 'boolean') {
      if (typeof val === 'boolean') {
        out[key] = val;
      } else {
        warnings.push(`${where}: expected true or false, default used`);
        out[key] = def;
      }
    } else if (typeof def === 'number') {
      // numeric strings are accepted (expressions in n8n often return text)
      const n = typeof val === 'string' && val.trim() !== '' ? Number(val) : val;

      if (typeof n === 'number' && Number.isFinite(n)) {
        out[key] = n;
      } else {
        warnings.push(`${where}: expected a number, default used`);
        out[key] = def;
      }
    } else {
      out[key] = val; // plain string such as "version"
    }
  }

  // unknown keys are most likely typos, so they are reported
  if (isPlainObject(override)) {
    for (const key of Object.keys(override)) {
      if (!Object.prototype.hasOwnProperty.call(defaults, key)) {
        warnings.push(`${prefix}${key}: unknown setting ignored`);
      }
    }
  }

  return out;
}

function buildConfig(override) {
  const warnings = [];

  if (override !== undefined && override !== null && !isPlainObject(override)) {
    warnings.push('scoring_config: expected an object, defaults used');
    override = undefined;
  }

  const cfg = mergeConfig(DEFAULT_CONFIG, override, '', warnings);

  const { high, medium, low } = cfg.bands;

  if (!(high > medium && medium > low)) {
    warnings.push('bands: must satisfy high > medium > low, defaults used');
    cfg.bands = DEFAULT_CONFIG.bands;
  }

  if (cfg.min_coverage_for_fp < 0 || cfg.min_coverage_for_fp > 1) {
    warnings.push('min_coverage_for_fp: must be between 0 and 1, default used');
    cfg.min_coverage_for_fp = DEFAULT_CONFIG.min_coverage_for_fp;
  }

  // tiers are evaluated from the highest "min" to the lowest, so the
  // order in which the user wrote them does not matter
  for (const name of ['abuseipdb', 'virustotal', 'teamcymru']) {
    cfg.sources[name] = {
      ...cfg.sources[name],
      tiers: [...cfg.sources[name].tiers].sort((a, b) => b.min - a.min),
    };
  }

  return { cfg, warnings };
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

// Maps analyzer names (e.g. "TeamCymruMHR_1_0") and error-row
// service names (e.g. "TeamCymru") to one common key.
const SERVICES = [
  ['abuseipdb', /abuseipdb/i],
  ['maltiverse', /maltiverse/i],
  ['virustotal', /virustotal/i],
  ['teamcymru', /teamcymru/i],
  ['circl', /circl/i],
  ['maxmind', /maxmind/i],
  ['misp', /misp/i],
];

function serviceKey(name) {
  const text = String(name ?? '');

  for (const [key, re] of SERVICES) {
    if (re.test(text)) return key;
  }

  return text.toLowerCase() || 'unknown';
}

// Tiers must already be sorted from the highest "min" to the lowest
// (buildConfig takes care of that).
function tier(value, tiers) {
  for (const t of tiers) {
    if (value >= t.min) return t.points;
  }

  return 0;
}

// Finds a Cortex taxonomy entry by predicate (case-insensitive).
function taxonomy(summary, predicate) {
  return (summary?.taxonomies ?? []).find(
    t => String(t.predicate).toLowerCase() === predicate.toLowerCase()
  );
}

// Checks that the item looks like a Summary Enrichments output.
// Without these fields a score of 0 would only mean "no data", not "clean".
function checkInput(data) {
  const problems = [];

  const level = data.alert?.rule?.level;

  if (level === undefined || level === null || !Number.isFinite(Number(level))) {
    problems.push('alert.rule.level is missing');
  }

  if (!Array.isArray(data.cortex?.results)) {
    problems.push('cortex.results is missing');
  }

  if (!isPlainObject(data.processing)) {
    problems.push('processing is missing');
  }

  return problems;
}

// ------------------------------------------------------------
// Scoring of a single alert
// ------------------------------------------------------------

function scoreAlert(data, cfg, configWarnings, inputProblems) {
  const alert = data.alert ?? {};
  const results = data.cortex?.results ?? [];
  const processing = data.processing ?? {};
  const src = cfg.sources;

  // sources without a config entry (e.g. maxmind) are always active
  const active = key => src[key]?.enabled !== false;

  // point candidates: { source, points, reason, observable }
  const candidates = [];

  function add(source, points, reason, observable) {
    candidates.push({ source, points, reason, observable });
  }

  // --- 1. Wazuh rule level --------------------------------------
  const level = Number(alert.rule?.level ?? 0);

  const rulePoints = Math.round(
    Math.min(Math.max(level, 0), 15) * cfg.rule_level_multiplier
  );

  // --- 2. Known-good hashes (CIRCL) -----------------------------
  // Team Cymru MHR detection per hash, needed to check CIRCL "known" hashes
  const mhrPct = new Map();

  if (active('teamcymru')) {
    for (const r of results) {
      if (r.status !== 'complete') continue;
      if (serviceKey(r.analyzer) !== 'teamcymru') continue;

      const pct = Number(taxonomy(r.summary, 'detection_pct')?.value);

      if (Number.isFinite(pct)) {
        const key = String(r.observable);

        mhrPct.set(key, Math.max(pct, mhrPct.get(key) ?? 0));
      }
    }
  }

  const knownGood = new Set();

  if (active('circl')) {
    for (const r of results) {
      if (r.status !== 'complete') continue;
      if (serviceKey(r.analyzer) !== 'circl') continue;

      const t = taxonomy(r.summary, 'Result');

      if (String(t?.value).toLowerCase() === 'known') {
        const pct = mhrPct.get(String(r.observable));

        // a strong MHR detection overrides the known-good status
        if (pct !== undefined && pct >= src.circl.known_good_unless_mhr_pct) {
          add(
            'circl',
            0,
            `known in CIRCL, but MHR detection ${pct}% overrides known-good`,
            r.observable
          );
          continue;
        }

        knownGood.add(String(r.observable));

        add(
          'circl',
          src.circl.known_good,
          'hash known in CIRCL hashlookup (known-good)',
          r.observable
        );
      }
    }
  }

  // --- 3. Cortex analyzer results -------------------------------
  for (const r of results) {
    if (r.status !== 'complete') continue;

    const key = serviceKey(r.analyzer);

    if (!active(key)) continue;

    const s = r.summary ?? {};
    const obs = r.observable;

    if (key === 'abuseipdb') {
      if (s.whitelisted === true) {
        add('abuseipdb', src.abuseipdb.whitelisted, 'IP whitelisted in AbuseIPDB', obs);
      } else {
        const score = Number(s.abuse_confidence_score ?? 0);

        add(
          'abuseipdb',
          tier(score, src.abuseipdb.tiers),
          `abuse confidence ${score}`,
          obs
        );
      }
    }

    if (key === 'maltiverse') {
      const cls = String(s.classification ?? '').toLowerCase();
      const hist = Number(s.historical_matches?.count ?? 0);

      if (cls === 'malicious') {
        add('maltiverse', src.maltiverse.malicious, 'classification: malicious', obs);
      } else if (cls === 'suspicious') {
        add('maltiverse', src.maltiverse.suspicious, 'classification: suspicious', obs);
      } else if (cls === 'whitelist') {
        add('maltiverse', src.maltiverse.whitelist, 'classification: whitelist', obs);
      } else if (hist > 0) {
        add(
          'maltiverse',
          src.maltiverse.historical_only,
          `historical matches: ${hist}`,
          obs
        );
      } else {
        add('maltiverse', 0, `classification: ${cls || 'none'}`, obs);
      }
    }

    if (key === 'virustotal') {
      // taxonomy value looks like "2/91" (malicious engines / total engines)
      const t = taxonomy(s, 'GetReport');
      const m = /^(\d+)\s*\/\s*(\d+)$/.exec(String(t?.value ?? ''));

      if (m) {
        add(
          'virustotal',
          tier(Number(m[1]), src.virustotal.tiers),
          `VirusTotal ${m[1]}/${m[2]} engines`,
          obs
        );
      } else {
        add('virustotal', 0, 'VirusTotal: no parsable result', obs);
      }
    }

    if (key === 'teamcymru') {
      if (src.teamcymru.ignore_when_circl_known && knownGood.has(String(obs))) {
        add(
          'teamcymru',
          0,
          'MHR detections ignored: hash is known-good in CIRCL',
          obs
        );
        continue;
      }

      const pct = Number(taxonomy(s, 'detection_pct')?.value);

      if (Number.isFinite(pct)) {
        add(
          'teamcymru',
          tier(pct, src.teamcymru.tiers),
          `MHR detection ${pct}%`,
          obs
        );
      } else {
        add('teamcymru', 0, 'MHR: no record', obs);
      }
    }
  }

  // --- 4. MISP ---------------------------------------------------
  if (active('misp')) {
    let mispPoints = 0;
    let mispReason = null;

    for (const ind of data.misp?.unique_indicators ?? []) {
      const attrs = ind.attributes ?? [];
      const hasToIds = attrs.some(a => a.to_ids === true);
      const points = hasToIds ? src.misp.to_ids : src.misp.match;

      if (points > mispPoints) {
        mispPoints = points;

        mispReason = hasToIds
          ? `MISP hit (to_ids) for ${ind.value}`
          : `MISP hit for ${ind.value}`;
      }
    }

    if (mispPoints > 0) {
      add('misp', mispPoints, mispReason, undefined);
    }
  }

  // --- 5. One entry per source (max points) ----------------------
  const bySource = new Map();

  for (const c of candidates) {
    const current = bySource.get(c.source);

    if (!current || c.points > current.points) {
      bySource.set(c.source, c);
    }
  }

  const breakdown = [
    {
      source: 'rule_level',
      points: rulePoints,
      reason: `rule level ${level}`,
    },
    ...[...bySource.values()].map(c => ({
      source: c.source,
      points: c.points,
      reason: c.reason,
      observable: c.observable,
    })),
  ];

  const raw = breakdown.reduce((sum, b) => sum + b.points, 0);
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  // --- 6. Coverage: how many sources actually answered -----------
  const state = new Map(); // key -> { ok, failed }

  function mark(key, field) {
    if (!active(key)) return; // disabled sources do not affect coverage

    if (!state.has(key)) state.set(key, { ok: false, failed: false });
    state.get(key)[field] = true;
  }

  for (const r of results) {
    if (r.status === 'complete') mark(serviceKey(r.analyzer), 'ok');
  }

  for (const f of processing.failed ?? []) {
    mark(serviceKey(f.service ?? f.analyzer), 'failed');
  }

  // pending analyzers have no result yet, so they count as not answered
  for (const p of processing.pending ?? []) {
    mark(serviceKey(p.analyzer), 'failed');
  }

  // MISP without an error means the query ran (even with 0 hits)
  if (!state.has('misp')) mark('misp', 'ok');

  const sources = { ok: [], partial: [], failed: [] };

  for (const [key, st] of state) {
    if (st.ok && st.failed) sources.partial.push(key);
    else if (st.ok) sources.ok.push(key);
    else sources.failed.push(key);
  }

  const total =
    sources.ok.length +
    sources.partial.length +
    sources.failed.length;

  let coverage = total === 0
    ? 0
    : Number(
        (
          (sources.ok.length + 0.5 * sources.partial.length) / total
        ).toFixed(2)
      );

  // --- 7. Verdict ------------------------------------------------
  const { high, medium, low } = cfg.bands;

  let verdict =
    score >= high ? 'high' :
    score >= medium ? 'medium' :
    score >= low ? 'low' :
    'likely_false_positive';

  // missing data never closes an alert as a false positive
  if (
    (verdict === 'likely_false_positive' || verdict === 'low') &&
    coverage < cfg.min_coverage_for_fp
  ) {
    verdict = 'needs_review';
  }

  // an item without enrichment data is never reported as clean
  if (inputProblems.length > 0) {
    verdict = 'needs_review';
    coverage = 0;
  }

  return {
    score,
    verdict,
    coverage,
    sources,
    breakdown,
    config_version: cfg.version,
    ...(configWarnings.length > 0
      ? { config_warnings: configWarnings }
      : {}),
    ...(inputProblems.length > 0
      ? { input_problems: inputProblems }
      : {}),
  };
}

// ------------------------------------------------------------
// Process all input items
// ------------------------------------------------------------

return $input.all().map(item => {
  // the config travels with the item and is removed from the output
  const { scoring_config, ...rest } = item.json;

  const { cfg, warnings } = buildConfig(scoring_config);

  return {
    json: {
      ...rest,
      scoring: scoreAlert(rest, cfg, warnings, checkInput(rest)),
    },
  };
});
