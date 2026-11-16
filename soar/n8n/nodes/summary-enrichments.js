const rows = $input.all().map(item => item.json ?? {});
const errorRows = rows.filter(item => item.service && item.error !== undefined);

let alert = {};
try {
  alert = $('Normalize Alert').first().json ?? {};
} catch {}

function clean(obj) {
  return Object.fromEntries(
    Object.entries(obj).filter(([, value]) =>
      value !== undefined &&
      value !== null &&
      value !== '' &&
      !(Array.isArray(value) && value.length === 0)
    )
  );
}

function compactObservable(item) {
  if (typeof item === 'string') {
    return { value: item };
  }

  return clean({
    type: item.type ?? item.dataType ?? item.kind,
    value: item.data ?? item.value ?? item.observable ?? item.ioc,
    field: item.field ?? item.source_field ?? item.key,
    internal: item.internal ?? item.is_internal,
    cortex_eligible: item.cortex_eligible,
  });
}

const rawObservables = Array.isArray(alert.observables)
  ? alert.observables
  : [];

const observables = rawObservables.map(compactObservable);

const isAnalyzerRow = item =>
  Boolean(
    item.workerName ||
    item.workerDefinitionId ||
    item.analyzerName
  );

const mispRows = rows.filter(item =>
  item.Event && item.value !== undefined
);

const cortexRows = rows.filter(isAnalyzerRow);

const skippedIpRows = rows.filter(item => {
  if (item.record_type === 'cortex_skipped') {
    return true;
  }

  if (item.Event || isAnalyzerRow(item)) {
    return false;
  }

  const type = String(
    item.data_type ?? item.dataType ?? item.type ?? ''
  ).toLowerCase();

  const value =
    item.observable ??
    item.value ??
    item.data;

  return type.includes('ip') && value !== undefined && value !== null;
});

const groupedMisp = new Map();

for (const item of mispRows) {
  const type = item.type ?? 'unknown';
  const value = item.value ?? '';
  const key = `${type}\u0000${value}`;

  if (!groupedMisp.has(key)) {
    groupedMisp.set(key, {
      type,
      value,
      attributes: [],
    });
  }

  const threatLevel = item.Event?.ThreatLevel;

  const tags = Array.isArray(item.Tag)
    ? item.Tag.map(tag => tag.name).filter(Boolean)
    : [];

  groupedMisp.get(key).attributes.push(clean({
    comment: item.comment,
    to_ids: item.to_ids,
    disable_correlation: item.disable_correlation,
    event: clean({
      id: item.Event?.id,
      title: item.Event?.info,
      date: item.Event?.date,
      threat_level:
        typeof threatLevel === 'object'
          ? threatLevel?.name
          : threatLevel,
    }),
    tags,
  }));
}

function getCortexSummary(item) {
  const report = item.report;

  if (!report || typeof report !== 'object') {
    return undefined;
  }

  const full = report.full ?? {};

  const analyzer = String(
    item.workerName ??
    item.workerDefinitionId ??
    item.analyzerName ??
    ''
  ).toLowerCase();

  if (analyzer.includes('abuseipdb')) {
    const result = full.values?.[0] ?? {};
    const data = result.data ?? result;
    const categories =
      result.category_counts ??
      full.category_counts ??
      [];
    const freshness =
      result.freshness ??
      full.freshness ??
      {};

    return clean({
      whitelisted: data.isWhitelisted,
      abuse_confidence_score: data.abuseConfidenceScore,
      usage: data.usageType,
      country: data.countryName,
      country_code: data.countryCode,
      isp: data.isp,
      total_reports: data.totalReports,
      last_reported_at: data.lastReportedAt,
      reports_last_24h: freshness.last24h,
      reports_last_7d: freshness.last7d,
      top_categories: categories
        .slice()
        .sort((a, b) => (b.count ?? 0) - (a.count ?? 0))
        .slice(0, 3)
        .map(category => clean({
          name: category.category,
          count: category.count,
        })),
    });
  }

  if (analyzer.includes('maxmind')) {
    const country =
      full.country ??
      full.registered_country ??
      {};

    const continent = full.continent ?? {};

    return clean({
      country: country.name,
      country_code: country.iso_code,
      continent: continent.name,
      ip: full.traits?.ip_address,
    });
  }

  if (analyzer.includes('maltiverse')) {
    const blacklist = Array.isArray(full.blacklist)
      ? full.blacklist
      : [];

    const keywords =
      /malicious|compromis|malware|phish|botnet|ransomware|cobalt.?strike|rat|backdoor|trojan|infostealer|exploit|gamarue|mirai|emotet|adware|banker|virut|scam|fraud/i;

    const historicalMatches = blacklist.filter(entry => {
      const labels = Array.isArray(entry.labels)
        ? entry.labels
        : [];

      const benign = labels.some(label =>
        String(label).toLowerCase() === 'benign'
      );

      const threatLabel = labels.some(label =>
        /malicious|compromised|malware/i.test(String(label))
      );

      const threatDescription = keywords.test(
        String(entry.description ?? '')
      );

      return !benign && (threatLabel || threatDescription);
    });

    const examples = historicalMatches
      .slice()
      .sort((a, b) =>
        (Date.parse(b.last_seen ?? '') || 0) -
        (Date.parse(a.last_seen ?? '') || 0)
      )
      .slice(0, 3)
      .map(entry => clean({
        description: entry.description,
        source: entry.source,
        last_seen: entry.last_seen,
      }));

    return clean({
      classification: full.classification,
      country_code: full.asn_country_code ?? full.country_code,
      asn_cidr: full.asn_cidr,
      historical_matches: {
        count: historicalMatches.length,
        examples,
      },
    });
  }

  const taxonomies = (report.summary?.taxonomies ?? []).map(taxonomy =>
    clean({
      level: taxonomy.level,
      namespace: taxonomy.namespace,
      predicate: taxonomy.predicate,
      value:
        typeof taxonomy.value === 'string' &&
        taxonomy.value.toLowerCase() === 'unkown'
          ? 'unknown'
          : taxonomy.value,
    })
  );

  let message = full.message ?? full.status;

  if (
    typeof message === 'string' &&
    /^no record found for /i.test(message)
  ) {
    message = 'No record found';
  }

  return clean({
    taxonomies,
    message,
  });
}

const cortexResults = cortexRows.map(item => {
  const rawStatus = String(item.status ?? '').toLowerCase();
  const report = item.report;

  let status = rawStatus || 'unknown';

  if (status === 'success') {
    status = 'complete';
  }

  if (['waiting', 'inprogress', 'running'].includes(status)) {
    status = 'pending';
  }

  if (['failure', 'failed', 'error'].includes(status)) {
    status = 'failed';
  }

  if (report && typeof report === 'object' && report.success === false) {
    status = 'failed';
  }

  const summary = getCortexSummary(item);

  return clean({
    analyzer:
      item.workerName ??
      item.workerDefinitionId ??
      item.analyzerName,
    observable: item.data,
    data_type: item.dataType,
    status,
    summary:
      summary && Object.keys(summary).length > 0
        ? summary
        : undefined,
  });
});

const enrichedIpValues = new Set(
  cortexRows
    .filter(item =>
      String(item.dataType ?? '').toLowerCase() === 'ip'
    )
    .map(item => String(item.data ?? ''))
);

const failedValues = new Set(
  errorRows
    .filter(item => item.service !== 'MISP')
    .map(item => String(item.observable ?? ''))
);

const ipWithoutCortexResult = observables.filter(item =>
  String(item.type ?? '').toLowerCase().includes('ip') &&
  item.value !== undefined &&
  !enrichedIpValues.has(String(item.value)) &&
  !failedValues.has(String(item.value))
);

const skippedByFilterMap = new Map();

function addSkipped(item) {
  const value = item.value;

  if (value === undefined || value === null || value === '') {
    return;
  }

  const type = String(item.type ?? 'unknown');
  const key = `${type.toLowerCase()}\u0000${String(value)}`;

  skippedByFilterMap.set(key, clean({
    type,
    value,
    field: item.field,
    internal: item.internal,
    reason: item.reason,
  }));
}

for (const item of ipWithoutCortexResult) {
  const isInternal =
    item.internal === true ||
    String(item.internal).toLowerCase() === 'true';

  addSkipped({
    type: item.type ?? 'ip',
    value: item.value,
    field: item.field,
    internal: item.internal,
    reason: isInternal
      ? 'Internal IP; external Cortex lookup skipped'
      : 'No Cortex result for this IP',
  });
}

for (const item of skippedIpRows) {
  const value =
    item.observable ??
    item.value ??
    item.data;

  if (value === undefined || value === null || value === '') {
    continue;
  }

  const normalizedObservable = observables.find(
    observable => String(observable.value) === String(value)
  );

  const internal =
    item.internal ??
    item.is_internal ??
    normalizedObservable?.internal;

  const isInternal =
    internal === true ||
    String(internal).toLowerCase() === 'true';

  addSkipped({
    type:
      item.data_type ??
      item.dataType ??
      item.type ??
      normalizedObservable?.type ??
      'ip',
    value,
    field: item.field ?? normalizedObservable?.field,
    internal,
    reason:
      item.reason ??
      (
        isInternal
          ? 'Internal IP; external Cortex lookup skipped'
          : 'Excluded by Cortex eligibility filter'
      ),
  });
}

const skippedByFilter = [...skippedByFilterMap.values()];

const pending = cortexResults
  .filter(result => result.status === 'pending')
  .map(result => ({
    analyzer: result.analyzer,
    observable: result.observable,
    status: result.status,
  }));

const failed = [
  ...cortexResults
    .filter(result => result.status === 'failed')
    .map(result => ({
      analyzer: result.analyzer,
      observable: result.observable,
      status: result.status,
    })),
  ...errorRows.map(item => ({
    service: item.service,
    node: item.node,
    observable: item.observable,
    error: item.error,
  })),
];

const rule = alert.rule ?? {};
const agent = alert.agent ?? {};
const syscheck = alert.syscheck ?? {};

return [{
  json: {
    alert: clean({
      id: alert.alert_id ?? alert.id,
      timestamp: alert.timestamp,
      manager: alert.manager,
      source_format: alert.source_format,
      tlp: alert.tlp,
      rule: clean({
        id: rule.id,
        level: rule.level,
        description: rule.description,
      }),
      agent: clean({
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
      }),
      groups: alert.groups,
      mitre: clean({
        ids: alert.mitre_ids,
        tactics: alert.mitre_tactics,
        techniques: alert.mitre_techniques,
      }),
      syscheck: clean({
        path: syscheck.path,
        event: syscheck.event,
        sha256_before: syscheck.sha256_before,
        sha256_after: syscheck.sha256_after,
      }),
      observables,
    }),

    misp: {
      attribute_count: mispRows.length,
      unique_indicators: [...groupedMisp.values()],
    },

    cortex: {
      results: cortexResults,
      skipped_by_filter: skippedByFilter,
    },

    processing: {
      status: pending.length > 0
        ? 'partial'
        : failed.length > 0
          ? 'complete_with_errors'
          : 'complete',
      pending,
      failed,
    },
  },
}];
