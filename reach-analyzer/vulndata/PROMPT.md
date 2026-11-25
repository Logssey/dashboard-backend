# Drafting verdict data for one CVE

You are drafting the reachability data for one CVE in a Java library. A person reviews your draft before
it is used, so say what you are unsure of instead of guessing. Work only from the files in this folder.
Do not use what you remember about this CVE: releases differ, and the data must match the installed one.

## What you have

| File | Content |
|---|---|
| `advisory.md` | The advisory: summary, description, affected versions, references |
| `advisory.json` | The same advisory as the database returned it (CWE ids, CVSS) |
| `meta.json` | The package, the installed (vulnerable) version, the fixed versions, the fix commits |
| `fix-commits.diff` | The fix commits the advisory links (Java source only, tests left out). May be truncated or empty. It often holds the same fix once per maintained branch: its line numbers are those branches', not the installed release's |
| `candidates.tsv` | Methods of the installed release whose code the fix changed or removed, near the classes the fix commits touch |
| `method-diff.tsv` | Every method that differs between the installed and the fixed release (search it when the candidates miss something) |
| `methods-installed.tsv` | Every method of the installed release: `class`, `method`, `desc`, `lines` |
| `source/installed/`, `source/fixed/` | Source files of the candidate classes in both releases |
| `changed-lines.json` | For each source file, the lines of the installed release the fix replaced or deleted |
| `draft.template.json` | The draft with the fields that come from the advisory already filled in |
| `cache/` | The jars and sources jars of both releases and the whole patches. Read a class from the sources jar when you need code that is not under `source/` (a caller, a default value). Read only |

`candidates.tsv` columns: `status` (CHANGED, REMOVED), `class`, `method`, `desc`, `match` (how the method
relates to the fix commits: `class` same class, `name` same class name in another package, `package` same
package, `-` no fix commit to compare with), `lines` (source lines of the method), `fix_lines` (the lines
of the method the fix touched).

## What to write

Copy `draft.template.json` to `draft.json` and fill it in. Do not change `cve`, `ghsa`, `package`,
`severity` or `cvss_vector`.

### `entry.sinks`: the vulnerable functions

A sink is a method of the **installed** release such that "this method runs" means "the vulnerable code
can run". The analyzer reports the CVE reachable when the application can reach a sink.

- Start from the method the fix changed. That is usually the sink.
- The release diff decides, not the commit list: a fix commit that is not in the compared release (its
  methods are not in `method-diff.tsv`) did not fix the installed line. Leave its methods out and say so in
  `review.open_questions`.
- When the fixed method is shared by several operations and the advisory says only one of them is affected,
  keep the fixed method as the sink and name the narrower alternative (the affected caller) in
  `review.overreach_risks`. The reviewer chooses.
- Add a caller only when the fixed method itself cannot be a sink (for example the fix changed data, or
  the fixed method is private and inlined). The analyzer already follows calls inside the library.
- Leave out methods that run for every request or every use of the library (request dispatch, a shared
  parser loop, a constructor every caller uses). They make the CVE reachable in every application. When
  the vulnerable code is a branch inside such a method, keep the method as the sink only if nothing
  narrower exists, and say so in `review.overreach_risks`.
- Every sink must be a row of `methods-installed.tsv` with exactly that `class`, `method` and `desc`.
  Constructors are `<init>`, static initializers `<clinit>`, nested classes `Outer$Inner`.
- `confidence`: `high` when the fix commit changes this method for this CVE, `medium` when you inferred
  it (a caller, a release diff without a commit), `low` when it is a guess.
- `note` (optional, English): one sentence, only when a reviewer needs it.

### `entry.invocation_kind`

| Value | Meaning |
|---|---|
| `app_calls_library` | The vulnerable code runs only when application code calls the library. The call graph decides |
| `framework_calls_library` | A framework calls the library for the application (for example Spring MVC reading a request body with Jackson). No call from application code shows it |
| `framework_invokes` | The framework or server itself runs the code while handling a request, depending on configuration (for example a Tomcat authenticator) |
| `both` | Application code can call it, and a framework also calls it |

For every value except `app_calls_library` a person writes a rule (which facts about the application show
that the feature is in use). Put what that rule should look at in `review.rule_hint`.

Code the application picks by name through the JDK (a JCA provider algorithm, a service loader) is
`app_calls_library`: no framework runs it. Say in `review.open_questions` that the call goes through a name
lookup, which the call graph may not see.

### `entry.summary_ko`, `entry.summary_en`

`summary_ko`: one or two plain Korean sentences that a developer who has not read the advisory understands:
what goes wrong, under which condition, with what effect. No marketing words, no English sentence
structure. `summary_en`: the same in English, with the method name.

### `entry.sources`

Keep the URLs from the template (the advisory and the fix commits). Add a URL only if you read it here.

### `entry.l3`: the vulnerable region

L3 runs the application and records which lines executed. A region is the lines of the installed release
whose execution shows that the vulnerable code itself ran, not only the method around it.

- `version`: the installed version (already filled in).
- One region per method: `class`, `method`, `desc` as in `methods-installed.tsv`, `source` (the path of
  the outer class, `org/example/Outer.java`), `lines` as `[[first, last], …]`.
- Take the lines from `fix_lines` and `source/installed/`: the vulnerable statements, as narrow as the
  code allows. Every range must hold at least one of the method's `lines` (a line with executable code); a
  range of only declarations, comments or braces can never be seen executed.
- A fix that only **adds** a check leaves `fix_lines` pointing at the lines around the insertion. Choose
  the statement that is unsafe without the check.
- When the narrowest line also runs for harmless input (the fix added one term to a condition that is
  always evaluated), keep that line and say in `l3.note` what its execution does not show. A region is
  evidence that the code ran, not that the input was an attack. Whether its run also shows the condition
  the rule checks (a configuration or feature) depends on the line: a line that runs only when that feature
  is set up may show it, a line that runs in every application, whether or not the feature is in use, does
  not. How far a run of the region may raise the verdict is
  set by the person who writes the rule (`l3` of the verdict entry in `rules.json`); you only explain in
  `l3.note` what the region's execution shows and what it does not.
- Regions do not have to cover every sink. The narrowest place is enough; leave out a method that only
  loops over or forwards to it.
- When `lines` of the method is `-` the jar has no line numbers: leave `lines` out. The region is then the
  whole method; say so in `l3.note`. Do not take line numbers from `changed-lines.json` or the source files
  in that case: nothing recorded at run time can be matched to them.
- When execution cannot tell (the fix changed only data such as a deny list), write `"regions": []` and
  say why in `l3.note`.
- `note` (English): what the region covers and what it leaves out.

### `review`: what the reviewer must check

- `trigger_conditions`: what must be true for the code to be vulnerable (configuration, input, feature in
  use). Required.
- `rule_hint`: for a kind other than `app_calls_library`, what in the application's code or configuration
  shows that the feature is used. Otherwise an empty string. You may name framework settings you know
  (a Spring Boot property, a servlet API call), marked as not confirmed from these files.
- `overreach_risks`: where this data could report reachable when it is not.
- `open_questions`: what you could not settle from the files.

Write these in Korean. Be specific: name the class, the method, the line.

## Rules

- Decide nothing about any application. This data says where the vulnerable code is, not whether a service
  is affected.
- Do not invent a method, a descriptor or a line number. If the files do not show it, leave it out and
  write an open question.
- If the fix commits do not match the installed release (renamed classes, a different major line), say so
  in `open_questions` and work from `method-diff.tsv` and the sources.
- The output is `draft.json` only, valid JSON, with the two objects `entry` and `review`. Change no other
  file. (`vulndata.py check` then compares the draft with the jar and writes `REVIEW.md` for the reviewer.)
