# Jackson 3 CVE reachability notes (installed: jackson-core / jackson-databind 3.1.5, `tools.jackson.*`)

Target: Spring Boot 4 / Spring Framework 7 / Java 21 REST service. Spring MVC's
`JacksonJsonHttpMessageConverter` (`tools.jackson.databind.json.JsonMapper`) deserializes
`@RequestBody` JSON. All five CVEs are HIGH, all CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
(availability-only DoS), assigned by HeroDevs CNA. Jackson 2.x shares every bug (same code, `com.fasterxml.*`).

Evidence gathered from: release notes + tagged source on `raw.githubusercontent.com` (GitHub web/API were blocked),
advisory aggregators (opencve/tenable/wiz/vulert), and local reproduction against the real
`jackson-*-2.16.1` jars in `/opt/gradle-8.14.3/lib/`.

Source + diffs saved under `/home/claude/reach-poc/data/research/jackson-src/`
(`core-3.1.5/`, `core-3.1.6/`, `core-3.1.7/`, `databind-3.1.5/…3.1.7/`, `release-notes/`, `diffs/`, `verify-3.2/`).

## How Spring MVC reaches Jackson (verified from Spring source)

`spring-web` v7.0.0 `AbstractJacksonHttpMessageConverter.readJavaType()`:
```
349  ObjectReader objectReader = mapper.readerFor(javaType);
355  if (isUnicode) return objectReader.readValue(inputStream);   // UTF-8/16/32 -> InputStream
359  else           return objectReader.readValue(reader);         // else InputStreamReader
```
So the request-body path uses an **InputStream or Reader** (UTF8StreamJsonParser / ReaderBasedJsonParser),
**never a DataInput**. Spring Boot 4 `JacksonAutoConfiguration` builds a plain `JsonMapper.builder()`
with no default typing, no problem handlers, no lowered StreamReadConstraints
(`grep` for `activateDefaultTyping|ProblemHandler|StreamReadConstraints` = none).
`configureForJackson2()` only flips date/enum/misc features (does not touch coercion or typing).

Key default constants (jackson-core 3.1.5 `StreamReadConstraints` / `ErrorReportConfiguration`):
`DEFAULT_MAX_NUM_LEN=1000`, `DEFAULT_MAX_STRING_LEN=100_000_000`, `DEFAULT_MAX_ERROR_TOKEN_LENGTH=256`,
`DEFAULT_MAX_DOC_LEN=-1` (off). databind default `ALLOW_COERCION_OF_SCALARS=true`,
`FAIL_ON_INVALID_SUBTYPE=true`, `ACCEPT_CASE_INSENSITIVE_VALUES=false`.

---

## CVE-2026-89407 — jackson-core ReDoS in `NumberInput.looksLikeValidNumber` (GHSA-p6pp-m3f8-5c89)

Fixed: core **3.1.7 / 3.2.2** (still vulnerable in 3.1.5 **and 3.1.6** — verified `PATTERN_FLOAT` count 6 in
3.1.6, 0 in 3.1.7). 2.x: 2.18.11/2.21.7/2.22.3. Method introduced in 2.17.0 → **2.16.x not affected**.

Release note (core 3.1.7): `#1649: Optimize `NumberInput.looksLikeValidNumber` [CVE-2026-89407]`.

Vulnerable code (3.1.5 `NumberInput.java`):
```
32  private final static Pattern PATTERN_FLOAT = Pattern.compile("[+-]?[0-9]*[\\.]?[0-9]+([eE][+-]?[0-9]+)?");
42  private final static Pattern PATTERN_FLOAT_TRAILING_DOT = Pattern.compile("[+-]?[0-9]+[\\.]");
626  return PATTERN_FLOAT.matcher(s).matches() || PATTERN_FLOAT_TRAILING_DOT.matcher(s).matches();
```
`[0-9]*[.]?[0-9]+` has adjacent quantifiers over the digit class → catastrophic/quadratic backtracking on
`digits...` + non-digit tail. 3.1.7 deletes both patterns and the `Pattern` import, replacing the body with a
single forward scan (`core-NumberInput-3.1.5-3.1.7.diff`).

databind call sites (3.1.5, reached in DEFAULT config on string→number coercion):
- `deser/std/StdDeserializer.java:1087` `_parseFloatPrimitive(...,String)`
- `deser/jdk/NumberDeserializers.java` `:710` Float, `:815` Double, `:926` Number, `:1126` BigDecimal
- `node/StringNode.java:341-397` `_tryParseAsInteger/Long/BigInteger/Float/Double/BigDecimal`
  (reached via public `asInt/asLong/asBigInteger/asFloat/asDouble/asDecimal` on a parsed node)

Local repro (exact 3.1.5 regex, `scratchpad/regexbench`): n=5k/10k/20k/40k digit+`x` → **121/316/1267/4595 ms**
(quadratic). Advisory reports ~74s for 160,000 chars. Default `maxStringLength`=20M does not help.

Reachability: **framework_invokes** — any `@RequestBody`/`readValue` target with a float/double/BigDecimal/Number
field, value sent as a JSON **string** (`{"price":"111…1x"}`).

---

## CVE-2026-89425 — jackson-core unbounded error-token in `UTF8DataInputJsonParser` (GHSA-7hhh-6rmp-j9qf)

Fixed: core **3.1.7 / 3.2.3** (verified `getMaxErrorTokenLength` absent in the DataInput parser in 3.1.5/3.2.2,
present 3.1.7/3.2.3). 2.x: 2.18.11/2.21.7/2.22.3. Introduced 2.8.0.

Release note (core 3.1.7): `#1698: `UTF8DataInputJsonParser` does not honor `maxErrorTokenLength` when reporting an unrecognized token [CVE-2026-89425]`.

Vulnerable code (3.1.5 `UTF8DataInputJsonParser._reportInvalidToken`, line 2968):
```
2975  try { while (true) {
2977      char c = (char) _decodeCharForError(ch);
2978      if (!Character.isJavaIdentifierPart(c)) break;
2981      sb.append(c);                         // <-- no maxErrorTokenLength check
2982      ch = _inputData.readUnsignedByte();
2983  } } catch (IOException e) { ; }
```
3.1.7 adds `maxTokenLength = _ioContext.errorReportConfiguration().getMaxErrorTokenLength()` and
`if (sb.length() >= maxTokenLength) { sb.append("..."); break; }` (`core-UTF8DataInputJsonParser-3.1.5-3.1.7.diff`).
The sibling `UTF8StreamJsonParser._reportInvalidToken` (3.1.5 line 4234) and `ReaderBasedJsonParser` (3.1.5 line 3124)
**already** enforce the cap — only the DataInput parser was missing it.

DataInput parser is built **only** via `createParser(DataInput)` / `readValue(DataInput,…)` / `readTree(DataInput)`
(`JsonFactory._createParser(... DataInput)` line 467 → `new UTF8DataInputJsonParser`). Spring's converter never
uses this path (see top). So:

Reachability: **app_calls_library**, `default_config_affected=false` — the parser is vulnerable in its default
config, but the app must explicitly choose a `DataInput` source. Not reachable by merely having `@RequestBody` JSON endpoints.

Local repro (real 2.16.1, `scratchpad/j2poc`): a 2,000,000-char bad token →
**DataInput exception message length = 2,000,109** vs **InputStream path = 367** (cap honored). Confirms the InputStream
path is safe and only DataInput is unbounded.

---

## CVE-2026-68497 — jackson-databind Duration/XMLGregorianCalendar unbounded parse (GHSA-q4xh-88c3-wmh7)

Fixed: databind **3.1.6 / 3.2.2** (one minor earlier than the other databind CVEs). 2.x: 2.18.10/2.21.6/2.22.2.

Release note (databind 3.1.6): `#6127: Add `StreamReadConstraints` number len constraint to `javax.xml.datatype.XMLGregorianCalendar` and `javax.xml.datatype.Duration` [CVE-2026-68497]`.

Vulnerable code (3.1.5 `ext/CoreXMLDeserializers.java` `Std._deserialize`):
```
136  case TYPE_DURATION:   return _dataTypeFactory.newDuration(value);          // no length check
140  case TYPE_G_CALENDAR: ... _dataTypeFactory.newXMLGregorianCalendar(value); // no length check
```
3.1.6 inserts `_validateTimestampLength(ctxt, value)` before each (`databind-CoreXMLDeserializers-3.1.5-3.1.6.diff`);
the new `StdDeserializer._validateTimestampLength` throws `StreamConstraintsException` when
`value.length() > StreamReadConstraints.getMaxNumberLength()` (default 1000). Root cause is the JDK's O(n^2)
`BigInteger(String)`/`BigDecimal(String)` parsing of the components.

Default-registered: `OptionalHandlerFactory.instance` (3.1.5) maps `javax.xml.` types to
`CoreXMLDeserializers.findBeanDeserializer`, wired from `BasicDeserializerFactory.findOptionalStdDeserializer`.
No opt-in; `javax.xml.datatype` is in the JDK.

Reachability: **both** — framework_invokes once a `Duration`/`XMLGregorianCalendar` field exists on a JSON endpoint
target; app_calls_library if the app reads those types directly. Not reachable if no such type appears in the model.

Local repro (real 2.16.1, Duration field): digits=100k/200k/400k → **236 / 707 / 2544 ms** (quadratic).

---

## CVE-2026-91776 — jackson-databind unbounded type-id cache in `TypeDeserializerBase` (GHSA-wv8q-qhhj-9h54)

Fixed: databind **3.1.7 / 3.2.3** (verified `MAX_CACHED_TYPE_IDS` absent 3.2.2, present 3.2.3). 2.x: 2.18.11/2.21.7/2.22.3.

Release note (databind 3.1.7): `#6203: Prevent unbounded growth of type id cache in `TypeDeserializer` [CVE-2026-91776]`.

Vulnerable code (3.1.5 `jsontype/impl/TypeDeserializerBase._findDeserializer`):
```
147  ValueDeserializer<Object> deser = _deserializers.get(typeId);
...  // on unknown id, falls back via _findDefaultImplDeserializer / _handleUnknownTypeId (problem handler)
200  _deserializers.put(typeId, deser);   // unbounded: keyed by raw attacker typeId, no size/length cap
```
`_deserializers` is a `ConcurrentHashMap` shared across the mapper's lifetime (constructor line 73/84).
3.1.7 adds `MAX_CACHED_TYPE_IDS=1000`, `MAX_CACHED_TYPE_ID_LENGTH=256`, skips caching the problem-handler /
NullifyingDeserializer fallback, skips ids longer than 256, and clears the map when full
(`databind-TypeDeserializerBase-3.1.5-3.1.7.diff`).

Preconditions (so `default_config_affected=false`): fallback polymorphic typing where unknown ids do **not**
hard-fail — `@JsonTypeInfo(use=Id.NAME/CLASS/…, defaultImpl=…)`, or a `DeserializationProblemHandler`, or
`activateDefaultTyping`; plus a long-lived shared mapper (Spring's default singleton). With default
`FAIL_ON_INVALID_SUBTYPE=true` and no defaultImpl/handler, an unknown id throws and nothing is cached.

Call sites of `_findDeserializer`: `AsPropertyTypeDeserializer._deserializeTypedForId:119`,
`AsArrayTypeDeserializer._deserialize:92`, `AsWrapperTypeDeserializer._deserialize:98`,
`TypeDeserializerBase._deserializeWithNativeTypeId:250`.

Reachability: **both** (needs app annotations/config, not reached by plain Spring JSON).

Local repro (real 2.16.1, `@JsonTypeInfo(use=NAME, defaultImpl=Impl.class)`): **10,000 distinct unknown ids →
10,000 retained entries** in `TypeDeserializerBase._deserializers` (via reflection). Confirms unbounded growth.

---

## CVE-2026-91777 — jackson-databind quadratic forward-reference resolution (GHSA-cxp5-3px4-pw24)

Fixed: databind **3.1.7 / 3.2.3** (verified `_unresolvedById` absent 3.2.2, present 3.2.3). 2.x: 2.18.11/2.21.7/2.22.3.
Sibling `#6205` fixes the same shape in `ObjectArrayDeserializer` (array variant, no separate CVE).

Release note (databind 3.1.7): `#6204: Avoid quadratic forward-reference resolution in Collection/Map deserializers [CVE-2026-91777]`.

Vulnerable code (3.1.5 `deser/jdk/CollectionDeserializer.java` `CollectionReferringAccumulator.resolveForwardReference`,
mirrored in `MapDeserializer`):
```
641  public void resolveForwardReference(ctxt, id, value) {
642      Iterator<CollectionReferring> it = _accumulator.iterator();   // full scan each resolution
...      if (ref.hasId(id)) { previous.add(value); previous.addAll(ref.next); return; }  // + merge
```
N references defined in reverse order → O(N^2). 3.1.7 replaces `_accumulator` with `_unresolvedById`
(`Map<Object,Deque<Referring>>`, O(1) lookup) + `_pending`/`_pendingStart` (each value moved once), and
`CollectionReferring`/`MapReferring` lose their `next` buffer, gaining `resolve/isResolved/resolvedValue`
(`databind-CollectionDeserializer-3.1.5-3.1.7.diff`, `databind-MapDeserializer-3.1.5-3.1.7.diff`).

Precondition (so `default_config_affected=false`): the accumulator is only built when
`_valueDeserializer.getObjectIdReader(ctxt) != null`, i.e. the element/value type uses **@JsonIdentityInfo**
(`CollectionDeserializer._deserializeWithObjectId:480` guarded by line 376;
`MapDeserializer._readAndBind:489` / `_readAndBindStringKeyMap:570`). Plain collections are unaffected.

Reachability: **both** (needs @JsonIdentityInfo in app model).

Local repro (real 2.16.1, `@JsonIdentityInfo` List, `scratchpad/j2poc`): reverse-order defs
N=8000/16000/32000 → **683 / 3422 / 13798 ms** vs forward-order **28 / 36 / 56 ms** — clearly quadratic.

---

## Jackson 2.x equivalents (for local testing with real 2.16.1 jars)

2.16.1 is itself affected by all five (same code; e.g. `com.fasterxml…UTF8DataInputJsonParser._reportInvalidToken`
had no cap, verified by `javap -c`; `CoreXMLDeserializers$Std._deserialize` calls `newDuration` directly;
`TypeDeserializerBase._findDeserializer` does unconditional `put`; `CollectionReferringAccumulator.resolveForwardReference`
does the List scan + `addAll`). NOTE: `NumberInput.looksLikeValidNumber` did NOT exist in 2.16.1 (added 2.17.0), so the
regex ReDoS (89407) cannot be reproduced on 2.16.1 — the standalone regex benchmark was used instead.
2.x fixed versions: 89407/89425/91776/91777 → 2.18.11, 2.21.7, 2.22.3; 68497 → 2.18.10, 2.21.6, 2.22.2.

Package differences 2.x vs 3.x: `com.fasterxml.jackson.*` vs `tools.jackson.*`; NumberDeserializers/CollectionDeserializer/
MapDeserializer live under `deser.std` in 2.x but `deser.jdk` in 3.x; `TextNode` (2.x) ≈ `StringNode` (3.x);
`IOException` in 2.x signatures vs `JacksonException`/none in 3.x.
