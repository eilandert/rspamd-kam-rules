# rspamd-kam-rules

**Transpile SpamAssassin's KAM.cf ruleset into a single native Rspamd Lua plugin.**

> 📖 **Full write-up:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/) — why the naive `spamassassin` module approach bites, and how this converter avoids it.

## Two spam fighters, one ruleset

**SpamAssassin** is the elder. Its KAM.cf ruleset (Kevin A. McGrail's collection of
3,000+ patterns) has caught phishing, malware droppers, and lottery scams for years.
It's genuinely good — and written in SpamAssassin's dialect, which expects
SpamAssassin to run it.

**Rspamd** uses an event-driven C core with Lua extension points and a native regexp
engine. Running KAM.cf there avoids a separate SpamAssassin daemon and its Perl
runtime.

You *can* feed the raw `.cf` to Rspamd's built-in `spamassassin` module. But that
parses all ~6,500 lines on every config load, carries hundreds of rules it can't run,
and never remaps SpamAssassin symbol names like `SPF_PASS` to Rspamd's `R_SPF_ALLOW`.
Meta rules that reference unmapped symbols compile fine and then silently never fire.

## What this does instead

This converter reads KAM.cf with a real parser and emits one self-contained `kam.lua`:

- **Maps symbols** — `SPF_PASS` → `R_SPF_ALLOW`, `DKIM_VALID` → `R_DKIM_ALLOW`, the
  `URIBL_*` family → Rspamd's SURBL/DBL symbols, so metas actually resolve and fire.
- **Prunes dead metas** — fixpoint dependency resolution drops any meta whose
  transitive dependencies aren't reachable on *your* Rspamd (180 in the current run),
  recording the missing symbols in the report.
- **Preserves semantics** — regex flags, header modes (`addr`/`name`/`raw`/`case`),
  `replace_tag`/`replace_rules` expansion, body matching against Subject unless
  `nosubject` is set, and message-global `tflags multiple maxhits=N` scoring all
  survive.
- **Registers properly** — every scored rule becomes a virtual child of the
  `KAM_RULES_MODULE` callback symbol and joins the `KAM` symbol group, so the whole
  ruleset is one organisational unit in the UI/history. External symbols used by
  metas are registered as scheduler dependencies. Regexps compile via
  `rspamd_regexp.create`; metas via `rspamd_expression.create`.
- **Skips the unsupported** — `askdns`, `eval:` plugin functions, and friends go to
  the report, not the output.
- **Pins the source** — each generated `kam.lua` carries the SHA-256 of the exact
  KAM.cf it was built from.

The result is one generated `kam.lua` plus a small top-level module configuration.

## What gets converted

Out of KAM.cf's ~6,500 lines, the current run converts **3,249 rules**:

| Type | Count | Catches |
|---|---|---|
| body | 1,179 | message-text patterns |
| header | 1,117 | Subject / From / Message-ID etc. |
| meta | 690 | combined-signal verdicts |
| uri | 156 | malicious redirectors, phishing domains |
| rawbody | 67 | base64-obfuscated payloads pre-decode |
| mimeheader | 38 | forged attachments |
| full | 2 | whole RFC 822 message |

180 meta rules are deliberately dropped because they depend on symbols the target
Rspamd doesn't provide (SA-plugin symbols, DNS lists, `eval:` functions).

## Install

```bash
# Download the pre-compiled plugin into your Rspamd plugins directory
sudo wget -O /etc/rspamd/plugins.d/kam.lua \
  https://raw.githubusercontent.com/eilandert/rspamd-kam-rules/main/dist/kam.lua
sudo chmod 0644 /etc/rspamd/plugins.d/kam.lua
```

Merge this block into `/etc/rspamd/rspamd.conf.local` once. A custom file in
`plugins.d` is disabled unless its top-level module is configured:

```ucl
kam {
    enabled = true;
}
```

Then validate and restart:

```bash
sudo rspamadm configtest
sudo systemctl restart rspamd
sudo journalctl -u rspamd --since "5 minutes ago" |
  grep "generated KAM Lua rules"
```

The plugin is regenerated **daily at 3am UTC** via GitHub Actions, but only commits a
new `dist/kam.lua` when KAM.cf upstream content changes. The updater downloads once,
compares its SHA-256 with `dist/report.json`, and passes that same hash to the
converter for verification.

### Symbol group

Every KAM symbol is registered into the `KAM` group (child of the
`KAM_RULES_MODULE` callback). The group is **uncapped** — symbols score additively.
To cap the group's total positive contribution, drop `config/groups.conf` in as
`/etc/rspamd/local.d/groups.conf` and set `max_score`:

```
group "KAM" {
    max_score = 100;   # ceiling for the whole ruleset's contribution
}
```

## Build it yourself

```bash
# Uses your production symbol set so the output adapts to your stack
python3 kam_rspamd.py                       # downloads KAM.cf, writes dist/kam.lua + dist/report.json
python3 kam_rspamd.py --input KAM.cf        # convert a local file instead
python3 -m unittest discover -s tests       # run the test suite
bash tests/test_runtime.sh                  # run integration tests with Docker + Rspamd
```

For a pinned local source, add
`--expected-sha256 0123456789abcdef...` and conversion will fail if the bytes do
not match.

Two config files describe the target Rspamd:

- `config/external-symbols.txt` — dump of your production Rspamd `/symbols` endpoint
  (everything your instance can raise). KAM-defined symbols are excluded.
- `config/unavailable-symbols.txt` — KAM symbols you know aren't registered on your
  stack, listed explicitly so dependent metas get pruned.

Regenerate the symbol dump whenever you change stacks, then rebuild.

## Performance note (read this)

The generated plugin compiles its regexps at Rspamd startup and evaluates scored
rules and their dependencies lazily during the callback. It does not promise a
single Hyperscan pass, and its throughput depends on the message corpus, enabled
rules, Rspamd build, and hardware.

The converter's primary benefits over loading raw SpamAssassin syntax are
**correctness and hygiene**: mapped external symbols, explicit scheduler
dependencies, dead metas pruned, and one auditable artifact pinned to a known
KAM.cf hash. Benchmark both approaches on your own traffic before making performance
claims.

## License

**This project** (the converter) is MIT-licensed.

**KAM.cf** remains under Apache-2.0 with its original authorship (Kevin A. McGrail,
with Joe Quinn, Karsten Bräckelmann, Bill Cole, and Giovanni Bechis). The generated
`dist/kam.lua` is a derivative work of KAM.cf and inherits its Apache-2.0 license.

## See also

- **Article:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/)
- **Background:** [Rspamd Explained: How Modern Spam Filtering Actually Works](https://deb.myguard.nl/2026/05/rspamd-explained-modern-spam-filtering-bayes-neural-rbl/)
- **KAM.cf upstream:** [mcgrail.com/downloads/KAM.cf](https://mcgrail.com/downloads/KAM.cf)
- **Rspamd:** [rspamd.com](https://rspamd.com)
