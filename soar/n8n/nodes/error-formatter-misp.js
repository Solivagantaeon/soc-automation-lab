/**
 * SOC - Error Formatter (MISP)
 * Stage: Failure handling (#72)
 *
 * Code node "Error Formatter - MISP".
 * Input:  error output of "Get a filtered list of attributes"
 * Output: one record per failed MISP query:
 *         { service, node, observable, error, timestamp }
 *
 * n8n Code node:
 * Mode: Run Once for All Items
 * Language: JavaScript
 *
 * MISP searches all observables of an alert in one query, so the record lists
 * all non-internal observables. The MISP branch can run before
 * "Dedupe Cortex Observables", so the values are also read from
 * "Normalize Alert", where observables use the Cortex format { dataType, data }.
 */

const SERVICE_NAME = 'MISP';
const SOURCE_NODES = ['Normalize Alert', 'Dedupe Cortex Observables'];

const safe = fn => { try { return fn() ?? []; } catch { return []; } };

const collect = (o, out = [], d = 0) => {
  if (!o || typeof o !== 'object' || d > 6) return out;
  const type  = o.type ?? o.dataType;
  const value = o.value ?? o.data;
  if (typeof value === 'string' && typeof type === 'string' && o.internal !== true) out.push(value);
  for (const v of Object.values(o)) collect(v, out, d + 1);
  return out;
};

const checked = [...new Set(SOURCE_NODES.flatMap(n => safe(() => $(n).all())).flatMap(x => collect(x.json)))];

return $input.all().map((input, i) => ({
  json: {
    service:    SERVICE_NAME,
    node:       $prevNode.name,
    observable: checked.join(', ') || 'unknown',
    error:      input.json?.error?.message ?? input.json?.error ?? 'unknown',
    timestamp:  new Date().toISOString(),
  },
  pairedItem: { item: i },
}));
