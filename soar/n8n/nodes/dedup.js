const WINDOW_MS = 7 * 60 * 1000; // dedup window, 7 minutes

// temp for time
const now = Date.now();

// data from n8n
const store = $getWorkflowStaticData('global');

// take store.dedup if store.dedup void take empty {}
store.dedup = store.dedup ?? {};

// if alert has been seen in WINDOWS_MS delete 
for (const [k, v] of Object.entries(store.dedup)) {
  if (now - v.first_seen > WINDOW_MS) delete store.dedup[k];
}


return $input.all().map(item => {
  const key = item.json.dedup_key;
  const hit = store.dedup[key];

  if (hit) {
    hit.count++;
    return { json: { ...item.json, is_duplicate: true,
      duplicate_count: hit.count, first_seen: hit.first_seen } };
  }

  store.dedup[key] = { first_seen: now, count: 1 };
  return { json: { ...item.json, is_duplicate: false, duplicate_count: 1 } };
});
