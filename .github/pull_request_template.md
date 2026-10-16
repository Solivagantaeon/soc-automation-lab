## Co zmienia ten PR

<!-- 1–3 zdania. Podlinkuj issue: Closes #12 -->

## Jak to przetestowałem/am w labie

<!-- Konkretnie: jaki alert / komenda / co było widać w Wazuh, Shuffle, TheHive. Zrzut ekranu mile widziany (bez kluczy i haseł!). -->

## Checklista

- [ ] Brak haseł, kluczy API, tokenów i URL-i webhooków (eksporty przepuszczone przez `scripts/sanitize_export.py`)
- [ ] Zrzuty ekranu nie pokazują kluczy, haseł ani publicznego IP
- [ ] `pre-commit run --all-files` przechodzi
- [ ] Dokumentacja zaktualizowana (README / runbook / ADR), jeśli dotyczy
