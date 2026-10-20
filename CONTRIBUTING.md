# Jak pracujemy w tym repo

Krótko: **nic nie trafia na `main` bez Pull Requesta**, **żadnych sekretów w repo**, każda zmiana ma test.

## 1. Pierwsze uruchomienie (raz, na swoim komputerze)

```bash
git clone <adres-repo>
cd soc-automation-lab
pip install pre-commit                                          # albo: pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push  # kontrola przed każdym commitem i pushem
```

Test: `pre-commit run --all-files` → wszystko „Passed”.

Ustaw w gicie **adres no-reply z GitHuba**, nie prywatny e-mail: adres autora jest publiczny w każdym commicie. Znajdziesz go w GitHub → **Settings → Emails**; zaznacz tam też *Keep my email addresses private* i *Block command line pushes that expose my email*. Commity dalej liczą się do Twojego profilu.

```bash
git config user.name  "Imię Nazwisko"   # albo login - to też jest publiczne
git config user.email "<id>+<login>@users.noreply.github.com"
```

## 2. Codzienny cykl pracy

1. Weź zadanie z zakładki **Issues** (albo załóż nowe), przypisz się.
2. Utwórz gałąź od aktualnego `main`:
   ```bash
   git switch main && git pull
   git switch -c feat/12-shuffle-cortex-step   # typ/numer-issue-krotki-opis
   ```
   Typy gałęzi: `feat/`, `fix/`, `docs/`, `detection/`, `chore/`.
3. Commituj małymi krokami. Format wiadomości:
   ```
   feat(shuffle): dodaj krok cortex_run do workflow triage
   fix(wazuh): popraw filtr integracji na rule_id 86601
   docs: opisz konfigurację MISP w TheHive
   ```
4. `git push -u origin <gałąź>` → otwórz **Pull Request** do `main`, wypełnij szablon.
5. Minimum jedna osoba z zespołu robi review. Po akceptacji: **Squash and merge**.

## 3. Zasady dotyczące sekretów (najważniejsze)

Repo będzie publiczne. Wszystko, co raz trafi do historii gita, zostaje w niej na zawsze — nawet jeśli potem usuniesz plik.

**Nigdy nie commitujemy:**
- haseł, kluczy API (Wazuh, Cortex, TheHive, MISP, Shuffle), tokenów, ciasteczek sesji,
- kluczy prywatnych WireGuard / SSH / certyfikatów TLS,
- adresów URL webhooków Shuffle (każdy, kto zna URL, może uruchomić workflow),
- publicznego adresu IP domowej sieci ani danych logowania do routera,
- plików `credentials.txt`, `.env`, kopii zapasowych VM, zrzutów pamięci.

**Zamiast tego:** wartości zastępcze w stylu `<CORTEX_API_KEY>` i plik `.env.example`.

**Eksport workflow z Shuffle / fragmenty `ossec.conf`** zawsze przepuszczaj przez skrypt:

```bash
python3 scripts/sanitize_export.py eksport.json -o soar/shuffle/workflows/soc-automation-v1.0.json
python3 scripts/sanitize_export.py --check .   # musi zwrócić 0 znalezisk
```

**Wgrywasz plik przez przeglądarkę („Add files via upload”)?** Hooki `pre-commit` wtedy nie działają, a commit jest od razu publiczny. Najpierw sprawdź plik u siebie: `python3 scripts/sanitize_export.py --check plik`, a zrzut ekranu: `python3 scripts/check_images.py --ocr zrzut.png`. Szczegóły, prywatna lista `.leakcheck-local` (Twoje IP, nazwisko) i co robić po wycieku: [SECURITY.md](SECURITY.md).

Na Windowsie zamiast `python3` wpisz `python`. Potem i tak przejrzyj diff wzrokiem — skrypt łapie typowe przypadki, nie wszystkie.

**Jeśli sekret jednak trafił do repo:** od razu napisz na kanale zespołu, **zmień/unieważnij ten klucz w systemie** (to jest właściwa naprawa), dopiero potem sprzątamy historię.

## 4. Co gdzie trzymamy

| Co | Gdzie |
|---|---|
| Reguły i dekodery Wazuha | `detection/wazuh/rules/`, `detection/wazuh/decoders/` |
| Konfiguracja agentów (`agent.conf`) | `detection/wazuh/agent-config/` |
| Fragmenty `ossec.conf` (integracje) | `detection/wazuh/integrations/` |
| Workflow Shuffle (JSON, po sanitizacji) | `soar/shuffle/workflows/` |
| Przykładowe alerty do testów | `samples/alerts/` (syntetyczne lub zanonimizowane) |
| Pomiary lejka alertów | `metrics/` |
| Decyzje architektoniczne | `docs/decisions/` (format ADR, kopiuj `0000-template.md`) |
| Instrukcje krok po kroku | `docs/runbooks/` |
| Zrzuty ekranu | `docs/images/` (sprawdź, czy nie widać na nich kluczy ani haseł!) |

## 5. Definicja „zrobione”

- [ ] zmiana przetestowana w labie (opis testu w PR),
- [ ] dokumentacja zaktualizowana (README / runbook / ADR),
- [ ] `pre-commit run --all-files` przechodzi,
- [ ] review od co najmniej jednej osoby.

## 6. Język
- Całe repo prowadzimy **po angielsku**: dokumentacja, komentarze w kodzie i konfiguracji, commity, nazwy gałęzi, Issues i Pull Requesty.
Po polsku rozmawiamy tylko na kanale zespołu.
