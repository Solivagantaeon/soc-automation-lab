# Checklista przed upublicznieniem repo

Do przejścia razem przed przełączeniem repo na **Public** (planowo po 10.11.2026).

## Zgody

- [ ] Cały zespół zgadza się na publikację (i na pokazanie imion/nazwisk w README).
- [ ] Prowadzący/uczelnia nie ma zastrzeżeń do publikacji materiałów z projektu.

## Sekrety i dane

- [ ] Pełny skan historii: `gitleaks git --config .gitleaks.toml --redact -v .` → 0 znalezisk.
- [ ] `python3 scripts/sanitize_export.py --check .` → 0 znalezisk.
- [ ] Ręczny przegląd: `docs/images/` (zrzuty ekranu), `samples/alerts/`, eksporty Shuffle.
- [ ] Brak publicznego IP domowej sieci: `git log -p | grep -E '<publiczny-adres>'` (sprawdź lokalnie, nie wpisuj adresu do repo).
- [ ] Brak prawdziwych danych osobowych (e-maile, nazwiska spoza zespołu) w alertach i logach.
- [ ] Jeśli cokolwiek wyciekło w historii: **najpierw zmienione klucze/hasła w systemach**, potem decyzja: przepisać historię (`git filter-repo`) albo opublikować nowe, czyste repo z jednym commitem.

## Portfolio

- [ ] README: sekcja *Results* z liczbami (lejek alertów przed/po), zrzuty ekranu lub GIF z demo.
- [ ] Sekcja *Team* uzupełniona — każdy opisuje swój wkład.
- [ ] Opis repo i *topics* na GitHubie: `soc`, `soar`, `wazuh`, `shuffle`, `thehive`, `misp`, `cortex`, `suricata`, `blue-team`, `home-lab`.
- [ ] Usunięte robocze/niedokończone pliki albo oznaczone jako *future work*.

## Po przełączeniu na Public

- [ ] Settings → Code security: włączony *Secret scanning* i *Push protection*.
- [ ] Ochrona gałęzi `main` (jeśli nie była włączona wcześniej).
- [ ] Każdy z zespołu przypina repo na swoim profilu (*Customize your pins*).
