// n8n Code node "Count Cortex Results" in workflow "SOC - Wazuh alert triage". History: git log.
const items = $input.all();

return items.map(item => {
  const data = item.json ?? {};

  const cortexResults = data.cortex?.results ?? [];
  const skipped = data.cortex?.skipped_by_filter ?? [];
  const processing = data.processing ?? {};

  const total = cortexResults.length;

  const completed = cortexResults.filter(
    result => result.status === 'complete'
  ).length;

  const failed = cortexResults.filter(
    result => result.status === 'failed' || result.status === 'error'
  ).length;

  const pending = processing.pending?.length ?? 0;

  const skippedCount = skipped.length;

  const analyzerCounts = {};

  for (const result of cortexResults) {
    const name = result.analyzer ?? 'unknown';
    analyzerCounts[name] = (analyzerCounts[name] ?? 0) + 1;
  }

  return {
    json: {
      ...data,
      cortex_summary: {
        total,
        completed,
        failed,
        pending,
        skipped: skippedCount,
        analyzer_counts: analyzerCounts,
        processing_status: processing.status ?? 'unknown'
      }
    }
  };
});
