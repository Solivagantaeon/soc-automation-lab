# Metrics

How we prove the reduction. One CSV per measurement run, e.g. `2026-10-20_baseline.csv`:

```
stage,alert_count,notes
raw,1000,24h window, all agents
after_dedup,250,
after_grouping,80,
after_enrichment,30,
incidents_for_analyst,10,
```

Always note the time window, agents included and rule-set version, so runs are comparable.
