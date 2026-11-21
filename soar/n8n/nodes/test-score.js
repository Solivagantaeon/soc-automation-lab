const fs = require('fs');

const code = fs.readFileSync('scoring.js', 'utf8');
const fileConfig = JSON.parse(fs.readFileSync('scoring_config.json', 'utf8')).scoring_config;

// returns the whole output item
const run = (data, config) => {
  const json = config === undefined ? data : { ...data, scoring_config: config };
  return new Function('$input', code)({ all: () => [{ json }] })[0].json;
};

const E3B0 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const mispErr = { service: 'MISP', node: 'Get a filtered list of attributes', observable: '8.8.8.8', error: 'x' };
const pairErr = svc => ({ service: svc, node: 'Get a report ' + svc, observable: '', error: 'x' });

// sample 2 (benign): level 5, empty-file hash known in CIRCL, AbuseIPDB and MISP failed
const p2 = {
  alert: { rule: { id: '5710', level: 5 } },
  misp: { attribute_count: 0, unique_indicators: [] },
  cortex: { results: [
    { analyzer: 'TeamCymruMHR_1_0', observable: E3B0, status: 'complete',
      summary: { taxonomies: [{ predicate: 'detection_pct', value: '37' }] } },
    { analyzer: 'CIRCLHashlookup_1_1', observable: E3B0, status: 'complete',
      summary: { taxonomies: [{ level: 'safe', predicate: 'Result', value: 'known' }] } },
  ] },
  processing: { pending: [], failed: [
    { service: 'AbuseIPDB', node: 'Execute AbuseIPDB', observable: '', error: 'x' }, mispErr] },
};

// sample 3 (suspicious): level 12, Maltiverse malicious, VirusTotal 2/91
const p3 = {
  alert: { rule: { id: '92213', level: 12 } },
  misp: { attribute_count: 0, unique_indicators: [] },
  cortex: { results: [
    { analyzer: 'Maltiverse_Report_1_0', observable: 'wicar.org', status: 'complete',
      summary: { classification: 'malicious', historical_matches: { count: 0, examples: [] } } },
    { analyzer: 'VirusTotal_GetReport_3_1', observable: 'http://wicar.org/test-malware.html', status: 'complete',
      summary: { taxonomies: [{ level: 'malicious', namespace: 'VT', predicate: 'GetReport', value: '2/91' }] } },
  ] },
  processing: { pending: [], failed: [
    pairErr('TeamCymru'), pairErr('TeamCymru'), pairErr('CirclHash'), pairErr('CirclHash'), mispErr] },
};

// synthetic: VirusTotal 12/91 with complete coverage
const q = {
  alert: { rule: { level: 5 } },
  misp: { attribute_count: 0, unique_indicators: [] },
  cortex: { results: [
    { analyzer: 'VirusTotal_GetReport_3_1', observable: 'http://x.test/', status: 'complete',
      summary: { taxonomies: [{ predicate: 'GetReport', value: '12/91' }] } },
  ] },
  processing: { pending: [], failed: [] },
};

let failures = 0;
function check(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  actual=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`}`);
}
const brief = o => [o.scoring.score, o.scoring.verdict, o.scoring.coverage];

// 1. no config node: defaults, results identical to v0.1
check('no config, sample 2', brief(run(p2)), [0, 'needs_review', 0.5]);
check('no config, sample 3', brief(run(p3)), [52, 'medium', 0.4]);
check('no config, no warnings', run(p3).scoring.config_warnings, undefined);

// 2. the shipped JSON equals the defaults
check('shipped JSON, sample 2', brief(run(p2, fileConfig)), [0, 'needs_review', 0.5]);
check('shipped JSON, sample 3', brief(run(p3, fileConfig)), [52, 'medium', 0.4]);
check('shipped JSON, no warnings', run(p3, fileConfig).scoring.config_warnings, undefined);

// 3. scoring_config is removed from the output
check('scoring_config stripped', 'scoring_config' in run(p3, fileConfig), false);

// 4. partial override: only one weight
check('maltiverse.malicious=40', run(p3, { sources: { maltiverse: { malicious: 40 } } }).scoring.score, 72);
check('maltiverse.malicious=40 verdict', run(p3, { sources: { maltiverse: { malicious: 40 } } }).scoring.verdict, 'high');

// 5. disabling a source removes its points and its coverage entry
const noVt = run(p3, { sources: { virustotal: { enabled: false } } });
check('virustotal disabled: score', noVt.scoring.score, 44);
check('virustotal disabled: coverage (1 of 4)', noVt.scoring.coverage, 0.25);

// 6. disabling CIRCL: MHR 37% counts again (10 + 8 = 18)
check('circl disabled: score', run(p2, { sources: { circl: { enabled: false } } }).scoring.score, 18);

// 7. teamcymru.ignore_when_circl_known=false: MHR 37% counts (10 - 10 + 8 = 8)
check('ignore_when_circl_known=false', run(p2, { sources: { teamcymru: { ignore_when_circl_known: false } } }).scoring.score, 8);

// 8. validation: typo in a key
const typo = run(p3, { sources: { maltivers: { malicious: 99 } } });
check('typo: score unchanged', typo.scoring.score, 52);
check('typo: warning', typo.scoring.config_warnings, ['sources.maltivers: unknown setting ignored']);

// 9. validation: wrong type
const bad = run(p3, { rule_level_multiplier: 'abc' });
check('wrong type: default used', bad.scoring.score, 52);
check('wrong type: warning', bad.scoring.config_warnings, ['rule_level_multiplier: expected a number, default used']);

// 10. numeric string is accepted
check('numeric string accepted', run(p3, { rule_level_multiplier: '3' }).scoring.score, 36 + 20 + 8);

// 11. validation: inconsistent bands
const bands = run(p3, { bands: { high: 10, medium: 40, low: 20 } });
check('bands invalid: defaults used', bands.scoring.verdict, 'medium');
check('bands invalid: warning', bands.scoring.config_warnings, ['bands: must satisfy high > medium > low, defaults used']);

// 12. tiers written in the wrong order are sorted
const unsorted = { sources: { virustotal: { tiers: [{ min: 1, points: 8 }, { min: 10, points: 25 }] } } };
check('unsorted tiers: 12/91 -> 25 pts', run(q, unsorted).scoring.score, 10 + 25);

// 13. invalid tiers fall back to the defaults
const badTiers = run(q, { sources: { virustotal: { tiers: 'many' } } });
check('invalid tiers: default used', badTiers.scoring.score, 10 + 25);
check('invalid tiers: warning', badTiers.scoring.config_warnings, ['sources.virustotal.tiers: expected a non-empty list of {min, points}, default used']);

// 14. config that is not an object
check('config is a string: warning', run(p3, 'oops').scoring.config_warnings, ['scoring_config: expected an object, defaults used']);

// 15. an item with only the config (the n8n case where input fields were dropped)
const empty = run({}, fileConfig);
check('empty item: needs_review', empty.scoring.verdict, 'needs_review');
check('empty item: coverage 0', empty.scoring.coverage, 0);
check('empty item: input_problems', empty.scoring.input_problems, [
  'alert.rule.level is missing',
  'cortex.results is missing',
  'processing is missing',
]);

// 16. a single missing part is enough
const noProcessing = { ...p3 };
delete noProcessing.processing;
check('missing processing: needs_review', run(noProcessing).scoring.verdict, 'needs_review');

// 17. complete input has no input_problems field
check('complete input: no input_problems', run(p3).scoring.input_problems, undefined);

// 18. CIRCL "known" versus Team Cymru MHR (lab case: EICAR is known in CIRCL, MHR 93%)
const hashRes = (obs, pct, circlResult) => [
  { analyzer: 'TeamCymruMHR_1_0', observable: obs, status: 'complete',
    summary: { taxonomies: [{ predicate: 'detection_pct', value: String(pct) }] } },
  { analyzer: 'CIRCLHashlookup_1_1', observable: obs, status: 'complete',
    summary: { taxonomies: [{ predicate: 'Result', value: circlResult }] } },
];
const withHashes = results => ({
  ...p3,
  cortex: { results: [...p3.cortex.results, ...results] },
  processing: { pending: [], failed: [mispErr] },
});

const strong = run(withHashes([...hashRes('h1', 93, 'known'), ...hashRes('h2', 93, 'known')]));
check('strong MHR overrides CIRCL: score', strong.scoring.score, 24 + 20 + 8 + 15);
check('strong MHR overrides CIRCL: circl entry', strong.scoring.breakdown.find(b => b.source === 'circl').points, 0);

const weak = run(withHashes([...hashRes('h1', 37, 'known'), ...hashRes('h2', 37, 'known')]));
check('weak MHR, CIRCL known: discount applies', weak.scoring.score, 24 + 20 + 8 - 10);

const mixed = run(withHashes([...hashRes('h1', 37, 'known'), ...hashRes('h2', 93, 'known')]));
check('one weak and one strong hash', mixed.scoring.score, 24 + 20 + 8 + 15);

const noException = run(
  withHashes([...hashRes('h1', 93, 'known'), ...hashRes('h2', 93, 'known')]),
  { sources: { circl: { known_good_unless_mhr_pct: 101 } } }
);
check('exception switched off (101)', noException.scoring.score, 24 + 20 + 8 - 10);

// 19. MISP: weak versus strong attribute types
// (issue: "Updater.exe" matched a to_ids file-name attribute and moved a
//  level 7 alert, 14 points, from low to medium)
const mispAlert = (indicators) => ({
  alert: { rule: { level: 7 } },
  misp: { attribute_count: indicators.length, unique_indicators: indicators },
  cortex: { results: [] },
  processing: { pending: [], failed: [] },
});
const ind = (type, value, toIds) => ({ type, value, attributes: [{ to_ids: toIds }] });
const mispEntry = o => o.scoring.breakdown.find(b => b.source === 'misp');
const MD5 = '0face841f7b2953e7c29c064d6886523';

const fileName = run(mispAlert([ind('filename', 'Updater.exe', true)]));
check('filename with to_ids: 8 points', mispEntry(fileName).points, 8);
check('filename with to_ids: stays low (22)', [fileName.scoring.score, fileName.scoring.verdict], [22, 'low']);
check('filename with to_ids: reason names the type',
  mispEntry(fileName).reason, 'MISP hit (to_ids) on weak type filename for Updater.exe');

const hashHit = run(mispAlert([ind('md5', MD5, true)]));
check('md5 with to_ids: 30 points', mispEntry(hashHit).points, 30);
check('md5 with to_ids: medium (44)', [hashHit.scoring.score, hashHit.scoring.verdict], [44, 'medium']);
check('md5 with to_ids: reason names the type',
  mispEntry(hashHit).reason, `MISP hit (to_ids) on type md5 for ${MD5}`);

check('filename without to_ids: 4 points', mispEntry(run(mispAlert([ind('filename', 'Updater.exe', false)]))).points, 4);
check('md5 without to_ids: 15 points', mispEntry(run(mispAlert([ind('md5', MD5, false)]))).points, 15);
check('type is compared without case', mispEntry(run(mispAlert([ind('FileName', 'x.exe', true)]))).points, 8);
check('composite type with a hash stays strong', mispEntry(run(mispAlert([ind('filename|sha256', 'x.exe|abc', true)]))).points, 30);
check('type missing from the list is strong', mispEntry(run(mispAlert([ind('some-new-type', 'v', true)]))).points, 30);
check('indicator without type is strong', mispEntry(run(mispAlert([{ value: 'v', attributes: [{ to_ids: true }] }]))).points, 30);

// a strong indicator wins over a weak one in the same alert
const both = run(mispAlert([ind('filename', 'Updater.exe', true), ind('ip-dst', '50.16.16.211', true)]));
check('strong indicator wins over weak: points', mispEntry(both).points, 30);
check('strong indicator wins over weak: reason',
  mispEntry(both).reason, 'MISP hit (to_ids) on type ip-dst for 50.16.16.211');

// config: weights and the list of weak types
check('to_ids_weak override', mispEntry(run(mispAlert([ind('filename', 'a.exe', true)]), { sources: { misp: { to_ids_weak: 12 } } })).points, 12);
check('match_weak override', mispEntry(run(mispAlert([ind('filename', 'a.exe', false)]), { sources: { misp: { match_weak: 6 } } })).points, 6);
check('weak_types without filename: filename is strong',
  mispEntry(run(mispAlert([ind('filename', 'a.exe', true)]), { sources: { misp: { weak_types: ['mutex'] } } })).points, 30);
check('weak_types normalised (case, spaces)',
  mispEntry(run(mispAlert([ind('mutex', 'm', true)]), { sources: { misp: { weak_types: [' MUTEX '] } } })).points, 8);

const emptyList = run(mispAlert([ind('filename', 'a.exe', true)]), { sources: { misp: { weak_types: [] } } });
check('empty weak_types: filename is strong', mispEntry(emptyList).points, 30);
check('empty weak_types: no warning', emptyList.scoring.config_warnings, undefined);

const badList = run(mispAlert([ind('filename', 'a.exe', true)]), { sources: { misp: { weak_types: 'filename' } } });
check('invalid weak_types: default list used', mispEntry(badList).points, 8);
check('invalid weak_types: warning', badList.scoring.config_warnings, ['sources.misp.weak_types: expected a list of text values, default used']);

// the shipped JSON still equals the built-in defaults
check('shipped JSON: filename match', mispEntry(run(mispAlert([ind('filename', 'Updater.exe', true)]), fileConfig)).points, 8);
check('shipped JSON: no warnings', run(mispAlert([ind('filename', 'Updater.exe', true)]), fileConfig).scoring.config_warnings, undefined);

console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
