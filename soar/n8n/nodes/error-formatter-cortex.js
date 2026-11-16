/**
 * SOC - Error Formatter (Cortex services)
 * Stage: Failure handling (#72)
 *
 * One Code node per Cortex service, named "Error Formatter - <service>".
 * Input:  error outputs of "Execute <service>" and "Get a report <service>"
 * Output: one record per failed observable:
 *         { service, node, observable, error, timestamp }
 *
 * n8n Code node:
 * Mode: Run Once for All Items
 * Language: JavaScript
 *
 * Change only the five constants below:
 *
 * | Formatter  | SERVICE_NAME | EXECUTE_NODE       | REPORT_NODE                | SOURCE_NODES                                   | TYPES    |
 * |------------|--------------|--------------------|----------------------------|------------------------------------------------|----------|
 * | Maltiverse | Maltiverse   | Execute Maltiverse | Get a report Maltiverse    | Normalize Alert, Dedupe Cortex Observables     | domain   |
 * | AbuseIPDB  | AbuseIPDB    | Execute AbuseIPDB  | Get a report AbuseIPDB     | Filter Cortex-Eligible IPs                     | ip       |
 * | TeamCymru  | TeamCymru    | Execute TeamCymru  | Get a report TeamCymru     | Normalize Alert, Dedupe Cortex Observables     | hash     |
 * | CirclHash  | CirclHash    | Execute CirclHash  | Get a report CirclHash     | Normalize Alert, Dedupe Cortex Observables     | hash     |
 * | VirusTotal | VirusTotal   | Execute VirusTotal | Get a report UnshortenLink | Normalize Alert, Dedupe Cortex Observables     | url      |
 *
 * How the failed observable is found:
 * An error item contains only the error message, and n8n item linking is not
 * reliable here (the Cortex node does not keep item links for more than one
 * item, and the polling loop loses them). The observables are therefore found
 * by comparing values:
 * - error from Execute:      sent observables of TYPES minus those with a job
 * - error from Get a report: created jobs minus jobs that already finished or
 *                            are still in the current polling round
 */

const SERVICE_NAME = 'CirclHash';
const EXECUTE_NODE = 'Execute CirclHash';
const REPORT_NODE  = 'Get a report CirclHash';
const SOURCE_NODES = ['Normalize Alert', 'Dedupe Cortex Observables'];
const TYPES        = ['hash'];

const safe  = fn => { try { return fn() ?? []; } catch { return []; } };
const jobId = j => j?.id ?? j?._id;

const collect = (o, out = [], d = 0) => {
  if (!o || typeof o !== 'object' || d > 6) return out;
  const type  = o.type ?? o.dataType;
  const value = o.value ?? o.data;
  if (typeof value === 'string' && TYPES.includes(type) && o.internal !== true) out.push(value);
  for (const v of Object.values(o)) collect(v, out, d + 1);
  return out;
};

const sent = [...new Set(SOURCE_NODES.flatMap(n => safe(() => $(n).all())).flatMap(x => collect(x.json)))];
const jobs = safe(() => $(EXECUTE_NODE).all(0)).map(x => x.json);
let failed;

if ($prevNode.name === EXECUTE_NODE) {
  const ok = new Set(jobs.map(j => j.data));
  failed = sent.filter(o => !ok.has(o));
} else {
  const run = $prevNode.runIndex ?? 0;
  const last = {};
  for (let r = 0; r < run; r++)
    safe(() => $(REPORT_NODE).all(0, r)).forEach(x => { last[jobId(x.json)] = x.json.status; });
  const now = new Set(safe(() => $(REPORT_NODE).all(0, run)).map(x => jobId(x.json)));
  failed = jobs
    .filter(j => !['Success', 'Failure'].includes(last[jobId(j)]) && !now.has(jobId(j)))
    .map(j => j.data);
}

return $input.all().map((input, i) => ({
  json: {
    service:    SERVICE_NAME,
    node:       $prevNode.name,
    observable: failed[i] ?? 'unknown',
    error:      input.json?.error?.message ?? input.json?.error ?? 'unknown',
    timestamp:  new Date().toISOString(),
  },
  pairedItem: { item: i },
}));
