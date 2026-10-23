# ADR 0002 – Choosing the SOAR engine for v0.2

- **Status:** Proposed
- **Date:** 2026-10-23
- **Authors:** @login
- **Issue:** #NN

## 1. Context

<!-- Dopiszcie, jeśli czegoś brakuje w wymaganiach. -->

The SOAR engine is the core of our pipeline: it receives Wazuh alerts, deduplicates and enriches them (MISP, Cortex), scores them and decides what reaches TheHive. v0.1 used Shuffle (tag [`v0.1`](https://github.com/Solivagantaeon/soc-automation-lab/tree/v0.1)). For v0.2 we want to compare the available options before choosing.

**Requirements:** self-hosted, free for a university project, works with Wazuh / TheHive / Cortex / MISP, handles thousands of alerts, workflows exportable to Git, ready before 10 Nov 2026.

## 2. Options considered

<!-- Research rynku: jakie jeszcze są rozwiązania poza Shufflem i n8n? Jeden wiersz = jedno narzędzie. -->

| Tool | Type | License | Notes | Source |
|---|---|---|---|---|
| | | | | |

## 3. Comparison

<!-- Kryteria to tylko przykłady. Znajdziesz kolejny ważny powód – dodaj wiersz. Kolumny = narzędzia z shortlisty. -->

| Criterion | Shuffle | n8n | … | Source |
|---|---|---|---|---|
| License and limits | | | | |
| Integrations (Wazuh, TheHive, Cortex, MISP) | | | | |
| Custom logic and testability | | | | |
| State / deduplication | | | | |
| Export to Git | | | | |
| Resource usage | | | | |

_Add rows for any other relevant criteria._

## 4. Research notes

<!-- Jedna podsekcja na temat: co sprawdzałeś, jak (docs / test w labie), co wyszło, linki. Reasercherujemy pod kątem odpowiadania na poniższe pytania -->

### 4.1 _Topic_ – @login

## 5. Questions to answer before the decision

<!-- Odpowiadamy w ramach researchu, zanim wybierzemy narzędzie. Można dopisywać pytania. -->

1. How does each tool handle deduplication and updating an existing TheHive alert?
2. What can we reuse from v0.1, and what must be rebuilt?
3. How does each tool handle security measures

## 6. Decision

<!-- Wspólnie, w dyskusji pod PR-em, z odwołaniem do §3 i §5. -->

- **Chosen engine:**
- **Why:**
- **Rejected options:**

## 7. Consequences

<!-- "What we lose" jest wstępnie opisane – rozbudujcie po researchu. -->

**What we gain:**

**What we lose:**
- the working Shuffle v1.0 workflow (must be rebuilt and retested),
- the built-in Wazuh → Shuffle integration and Shuffle's ready-made apps,
- deduplication behaviour from v1.0 (unless re-implemented),
- team know-how and time before the deadline.

**Risks:**

## 8. Feature parity (v0.1 vs v0.2)

<!-- Uzupełniamy dopiero po postawieniu i udokumentowaniu wybranego narzędzia. -->

_To be completed after deployment._
