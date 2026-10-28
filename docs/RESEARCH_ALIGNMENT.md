# Research alignment

## Requirements and experimental assumptions

The original proposal and the updated development instructions are the project requirements. They establish a native Windows endpoint application, early identification of file-encrypting ransomware-like behaviour, explainability, safe adaptive response, controlled experiments, and honest limits. They do not approve particular weights, thresholds, windows, or a final Windows collector.

The current numerical baseline is an engineering starting point: a 10-second window, Uncertain at 40 and High at 75, and maximum contributions of 30/35/25/10/0 for frequency/entropy/operations/spread/context. All are configurable development placeholders. The default response is alert-only. Existing first-version settings are migrated to that safer default rather than carrying forward automatic lab response.

## How the five indicators are represented

| Proposed indicator | Current representation | Interpretation limit |
| --- | --- | --- |
| File modification frequency | Modification observations per second and distinct modified paths per second over a defined window | Notifications are not exact kernel write calls; repeated writes and changes to many files differ |
| Entropy changes | Comparable before/after samples, significant-rise counts, and explicit unavailable samples | Compression and legitimate encryption can overlap; partial changes and inaccessible files may be missed |
| Repeated file operations | Operation histogram and adjacent transition types; rename suffix observations included as context | No compulsory Read → Write → Rename rule; collected adjacency is not proof of causality; folder reads unavailable |
| Directory spread | Distinct immediate parents of modified files; nested directories counted individually, ancestors not added | Wide spread can be benign; single-folder activity can still reach High risk |
| Process context | Known PID, creation time, executable, parent, metadata availability, and signature status | Context is not attribution; no validated contextual score is implemented; missing/familiar/signed does not decide safety |

Rename suffixes were a separate scored signal in the first prototype. They now support operation explanations while the fifth indicator is process context, matching the updated requirement. Context deliberately contributes zero until a specific rule can be justified and tested.

## Explainability and response

Each stored assessment includes measured features, indicator contributions, missing evidence, source attribution status, the experimental configuration, and a response reason. Low means continue observing; Uncertain means gather more evidence; High means alert and separately review response eligibility. A high score is not a ransomware confirmation.

The separate response component checks mode, corroborating evidence, cooperative source, stable metadata, exclusions for essential Windows processes, a revalidated registered child, and whether the worker is active and has not been released. It grants permission to attempt an action, not proof of success. OS control can fail, and the result belongs in the audit record.

## Source discipline

The project instructions list a research collection of 17 papers and name eight examples, including Ranker, RansomFisher, entropy-based studies, GuardFS, and Windows behavioural scoring work. Their full texts are not present in this repository. This implementation does **not** claim to have read or reproduced their methods, weights, experimental results, or datasets. No accuracy number is borrowed from those titles.

The paper names identify research questions for later reading: early evidence collection, entropy limitations, operation sequences, correlation, and mitigation trade-offs. Exact technical claims should only be added after the team supplies and reviews the relevant full texts, with page/section references. Supplying those papers is not a prerequisite for the current engineering improvements.

Microsoft's official API documentation was reviewed for concrete platform facts. The cited sources in [WINDOWS_MONITORING_FEASIBILITY.md](WINDOWS_MONITORING_FEASIBILITY.md) support the limitations of directory notifications, ETW correlation requirements, tracing permissions, and Sysmon event meanings. These API facts do not establish detection effectiveness.

## Evaluation alignment

The lab and automated checks validate software behaviour with harmless fixtures. The independent attribution probe measures whether a collector reports the known writer and what observations it misses. Offline ablation removes one indicator at a time from the same exported evidence without changing remaining weights; this allows inspection of score changes, not automatic claims that more indicators are faster or more accurate.

A formal FYP evaluation still needs labelled Windows workload runs, legitimate high-I/O and high-entropy controls, repeated conditions, frozen policies, and separate calibration/evaluation data. Use the definitions in [EVALUATION_PLAN.md](EVALUATION_PLAN.md), including undefined metrics and failed/undetected outcomes rather than silently replacing them with zero.
