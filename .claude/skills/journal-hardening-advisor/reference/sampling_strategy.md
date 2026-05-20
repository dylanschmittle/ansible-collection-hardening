# Sampling strategy

The journal analyzer is a single streaming pass. Memory is bounded by:

1. **Per-event-class reservoir sample.** For each event class we keep at most
   `--per-class-cap` (default 50) raw journal entries using Vitter-style
   reservoir sampling: keep the first K, then for the i-th item after K, swap
   into a random slot in [0, i) with probability K/i. This gives a uniform
   sample of the entries that matched a class, regardless of total count.

2. **Top-sources tracking.** For event classes whose classifier extracts a
   source IP (sshd failures, martian sources), we keep a per-class
   `{source_ip: count}` dict, capped at 10,000 distinct keys. New keys past
   the cap are dropped — heavy-hitter detection is not exact under
   adversarial spread, but the cap protects against memory blow-up on
   pathological journals.

3. **No global time bucketing yet.** The current implementation counts events
   per class but does not bucket by time; severity decisions are based on
   absolute counts. A future revision should add 5-minute buckets so we can
   tell "100 SSH failures in 1 minute" (flood) from "100 spread across a
   week" (background noise).

4. **No de-duplication.** journald can store the same MESSAGE many times
   (e.g. a flood from one source). We count all occurrences; the reservoir
   sample provides representative examples without re-counting.

The skill prints up to five short evidence excerpts per class
(`sample_evidence` field) so the user can verify what was caught.
