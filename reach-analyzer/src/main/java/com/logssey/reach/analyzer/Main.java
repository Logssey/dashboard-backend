package com.logssey.reach.analyzer;

import org.objectweb.asm.Type;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * reach v0 — function-level reachability of known-vulnerable methods in a Java application.
 *
 * <pre>
 * java -jar reach.jar --app build/libs/app.jar --spec vuln-functions.json --rules rules.json --out reach-result.json
 * </pre>
 */
public final class Main {
    static final String VERSION = "0.1.0";

    private static final Set<String> ENTRY_METHOD_ANNS = Set.of(
            "Lorg/springframework/web/bind/annotation/RequestMapping;",
            "Lorg/springframework/web/bind/annotation/GetMapping;",
            "Lorg/springframework/web/bind/annotation/PostMapping;",
            "Lorg/springframework/web/bind/annotation/PutMapping;",
            "Lorg/springframework/web/bind/annotation/DeleteMapping;",
            "Lorg/springframework/web/bind/annotation/PatchMapping;",
            "Lorg/springframework/web/bind/annotation/ExceptionHandler;",
            "Lorg/springframework/web/bind/annotation/ModelAttribute;",
            "Lorg/springframework/web/bind/annotation/InitBinder;",
            "Lorg/springframework/scheduling/annotation/Scheduled;",
            "Lorg/springframework/scheduling/annotation/Schedules;",
            "Lorg/springframework/context/event/EventListener;",
            "Lorg/springframework/transaction/event/TransactionalEventListener;",
            "Lorg/springframework/kafka/annotation/KafkaListener;",
            "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;",
            "Lorg/springframework/jms/annotation/JmsListener;",
            "Lorg/springframework/messaging/handler/annotation/MessageMapping;",
            "Lorg/springframework/messaging/simp/annotation/SubscribeMapping;",
            "Lorg/springframework/graphql/data/method/annotation/QueryMapping;",
            "Lorg/springframework/graphql/data/method/annotation/MutationMapping;",
            "Lorg/springframework/graphql/data/method/annotation/SchemaMapping;",
            "Lorg/springframework/context/annotation/Bean;",
            "Ljakarta/annotation/PostConstruct;",
            "Ljakarta/annotation/PreDestroy;",
            "Ljavax/annotation/PostConstruct;");

    private static final Set<String> COMPONENT_ANNS = Set.of(
            "Lorg/springframework/stereotype/Component;",
            "Lorg/springframework/stereotype/Service;",
            "Lorg/springframework/stereotype/Repository;",
            "Lorg/springframework/stereotype/Controller;",
            "Lorg/springframework/web/bind/annotation/RestController;",
            "Lorg/springframework/context/annotation/Configuration;",
            "Lorg/springframework/web/bind/annotation/ControllerAdvice;",
            "Lorg/springframework/web/bind/annotation/RestControllerAdvice;");

    public static void main(String[] argv) throws Exception {
        Path app = null;
        Path spec = null;
        Path rules = null;
        Path out = Path.of("reach-result.json");
        List<Path> libs = new ArrayList<>();
        int maxPath = 25;
        boolean phase2 = true;
        for (int i = 0; i < argv.length; i++) {
            switch (argv[i]) {
                case "--app" -> app = Path.of(argv[++i]);
                case "--lib" -> libs.add(Path.of(argv[++i]));
                case "--spec" -> spec = Path.of(argv[++i]);
                case "--rules" -> rules = Path.of(argv[++i]);
                case "--out" -> out = Path.of(argv[++i]);
                case "--max-path" -> maxPath = Integer.parseInt(argv[++i]);
                case "--no-phase2" -> phase2 = false;
                case "--version" -> {
                    System.out.println("reach " + VERSION);
                    return;
                }
                default -> {
                    usage("unknown argument: " + argv[i]);
                    return;
                }
            }
        }
        if (app == null || spec == null) {
            usage("--app and --spec are required");
            return;
        }

        long t0 = System.currentTimeMillis();
        ClassIndex idx = new ClassIndex();
        idx.load(app, libs);
        long tLoad = System.currentTimeMillis();
        System.err.printf("[reach] loaded %d app classes, %d library classes from %d jars (%d ms)%n",
                idx.appClasses, idx.libClasses, idx.jarClassCount.size(), tLoad - t0);
        if (idx.appClasses == 0) System.err.println("[reach] WARNING: no application classes found — check --app");

        Map<String, Object> specJson = Json.obj(Json.parse(Files.readString(spec, StandardCharsets.UTF_8)));
        Map<String, Object> rulesJson = rules == null ? new LinkedHashMap<>()
                : Json.obj(Json.parse(Files.readString(rules, StandardCharsets.UTF_8)));

        Code code = new Code(idx);
        Analyzer an = new Analyzer(idx, code);

        // Phase 1: framework entry points (Spring annotations, bean constructors, callbacks, main).
        List<String> entryExamples = new ArrayList<>();
        int phase1Entries = seedFrameworkEntries(idx, an, entryExamples);
        an.run();
        int phase1Reached = an.reached.size();
        // Phase 2: every first-party method (anything may be invoked by reflection or a framework).
        if (phase2) {
            an.phase = 2;
            for (ClassInfo c : idx.classes.values()) {
                if (!c.app) continue;
                for (MethodInfo m : c.methods.values()) {
                    if (m.hasBody()) an.reach(m.ref(), null, "entry:app-method", -1);
                }
            }
            an.run();
        }
        int strongReached = an.reached.size();
        an.enableWeakEdges();
        long tAn = System.currentTimeMillis();
        System.err.printf("[reach] reachable methods: %d (phase 1: %d), instantiated classes: %d (%d ms)%n",
                an.reached.size(), phase1Reached, an.instantiatedCount(), tAn - tLoad);

        Facts facts = new Facts(idx, code, an, rulesJson);
        facts.collect();

        List<Object> cveResults = new ArrayList<>();
        for (Object o : Json.arr(specJson.get("cves"))) {
            cveResults.add(evaluate(Json.obj(o), idx, an, maxPath));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tool", "reach " + VERSION);
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("app", app.toString());
        input.put("libs", libs.stream().map(Path::toString).toList());
        input.put("spec", spec.toString());
        input.put("rules", rules == null ? null : rules.toString());
        result.put("input", input);
        Map<String, Object> index = new LinkedHashMap<>();
        index.put("app_classes", idx.appClasses);
        index.put("library_classes", idx.libClasses);
        index.put("library_jars", idx.jarClassCount);
        index.put("duplicate_classes_ignored", idx.duplicates);
        index.put("warnings", idx.warnings.size() > 30 ? idx.warnings.subList(0, 30) : idx.warnings);
        result.put("index", index);
        Map<String, Object> analysis = new LinkedHashMap<>();
        analysis.put("algorithm", "RTA (on-the-fly), lambdas assumed invoked, reflection not modelled; "
                + "Object-method dispatch and JDK callbacks only in a second 'weak' stage");
        analysis.put("phase1_framework_entry_points", phase1Entries);
        analysis.put("phase1_entry_examples", entryExamples.size() > 20 ? entryExamples.subList(0, 20) : entryExamples);
        analysis.put("phase2_all_app_methods", phase2);
        analysis.put("reachable_methods", an.reached.size());
        analysis.put("reachable_methods_phase1", phase1Reached);
        analysis.put("reachable_methods_strong", strongReached);
        analysis.put("reachable_methods_weak_only", an.reached.size() - strongReached);
        analysis.put("instantiated_classes", an.instantiatedCount());
        analysis.put("virtual_call_sites", an.callSites);
        analysis.put("classes_parsed", code.parsedClasses);
        analysis.put("time_ms", System.currentTimeMillis() - t0);
        result.put("analysis", analysis);
        result.put("cves", cveResults);
        result.put("facts", facts.found);
        result.put("dto_roots", facts.roots);
        result.put("dto_type_tokens", facts.typeTokens());
        Files.writeString(out, Json.write(result), StandardCharsets.UTF_8);

        // console summary
        System.err.println();
        System.err.printf("%-16s %-22s %-10s %-10s%n", "CVE", "package", "pkg-reach", "sink-reach");
        for (Object o : cveResults) {
            Map<String, Object> r = Json.obj(o);
            Map<String, Object> p = Json.obj(r.get("package"));
            String sinkState = Boolean.TRUE.equals(r.get("sink_reachable_strong")) ? "YES"
                    : Boolean.TRUE.equals(r.get("sink_reachable")) ? "weak"
                    : Boolean.TRUE.equals(r.get("all_sinks_missing")) ? "MISSING" : "no";
            System.err.printf("%-16s %-22s %-10s %-10s%n", r.get("cve"), p.get("artifact"),
                    Boolean.TRUE.equals(p.get("reachable_strong")) ? "YES" : Boolean.TRUE.equals(p.get("reachable")) ? "weak"
                            : (Boolean.TRUE.equals(p.get("present")) ? "no" : "absent"),
                    sinkState);
        }
        System.err.println("[reach] wrote " + out);
    }

    private static void usage(String msg) {
        System.err.println("reach " + VERSION + ": " + msg);
        System.err.println("usage: java -jar reach.jar --app <boot-jar|dir> --spec vuln-functions.json [--rules rules.json]");
        System.err.println("                           [--lib <jar|dir>]... [--out reach-result.json] [--max-path 25] [--no-phase2]");
        System.exit(2);
    }

    // ------------------------------------------------------------------ entry points

    private static boolean annotatedWith(ClassIndex idx, List<Ann> anns, Set<String> wanted, int depth, Set<String> seen) {
        for (Ann a : anns) {
            if (wanted.contains(a.desc)) return true;
            if (depth > 0 && seen.add(a.desc)) { // meta-annotation, e.g. @RestController -> @Controller -> @Component
                ClassInfo at = idx.get(Type.getType(a.desc).getInternalName());
                if (at != null && annotatedWith(idx, at.anns, wanted, depth - 1, seen)) return true;
            }
        }
        return false;
    }

    private static int seedFrameworkEntries(ClassIndex idx, Analyzer an, List<String> examples) {
        int n = 0;
        List<ClassInfo> app = new ArrayList<>();
        for (ClassInfo c : idx.classes.values()) if (c.app) app.add(c);
        app.sort((a, b) -> a.name.compareTo(b.name));
        for (ClassInfo c : app) {
            if (c.isConcrete()) an.instantiate(c.name, null, -1); // frameworks create beans reflectively
        }
        for (ClassInfo c : app) {
            boolean component = annotatedWith(idx, c.anns, COMPONENT_ANNS, 3, new HashSet<>());
            for (MethodInfo m : c.methods.values()) {
                if (!m.hasBody()) continue;
                String why = null;
                if (annotatedWith(idx, m.anns, ENTRY_METHOD_ANNS, 2, new HashSet<>())) {
                    why = "entry:annotated";
                } else if (component && m.name.equals("<init>")) {
                    why = "entry:bean-constructor";
                } else if (m.isStatic() && m.name.equals("main") && m.desc.equals("([Ljava/lang/String;)V")) {
                    why = "entry:main";
                } else if (!m.isStatic() && !m.isPrivate() && !m.name.startsWith("<") && overridesExternal(idx, an, c, m)) {
                    why = "entry:framework-callback";
                }
                if (why != null) {
                    an.reach(m.ref(), null, why, -1);
                    n++;
                    if (examples.size() < 40) examples.add(why + " " + m.ref().shortName());
                }
            }
        }
        return n;
    }

    /** True if m overrides a method declared by a non-application supertype (framework or JDK). */
    private static boolean overridesExternal(ClassIndex idx, Analyzer an, ClassInfo c, MethodInfo m) {
        for (String sup : an.supertypes(c.name)) {
            if (sup.equals(c.name) || sup.equals("java/lang/Object")) continue;
            ClassInfo s = idx.info(sup);
            if (s == null || s.app) continue;
            MethodInfo sm = s.methods.get(m.name + m.desc);
            if (sm != null && !sm.isStatic() && !sm.isPrivate()) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ per-CVE evaluation

    private static Map<String, Object> evaluate(Map<String, Object> cve, ClassIndex idx, Analyzer an, int maxPath) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("cve", cve.get("cve"));
        Map<String, Object> pkg = Json.obj(cve.get("package"));
        String artifact = Json.str(pkg.get("artifact"));

        // package-level: is any method of the vulnerable library reachable?
        Set<String> jars = new HashSet<>();
        for (String jar : idx.jarClassCount.keySet()) {
            if (artifact != null && jar.startsWith(artifact + "-")) jars.add(jar);
        }
        Map<String, Object> pr = new LinkedHashMap<>();
        pr.put("artifact", artifact);
        pr.put("jars", new ArrayList<>(jars));
        pr.put("present", !jars.isEmpty());
        String best = null;
        long bestRank = Long.MAX_VALUE;
        int count = 0;
        for (Map.Entry<String, MRef> e : an.reached.entrySet()) {
            ClassInfo ci = idx.get(e.getValue().owner());
            if (ci == null || !jars.contains(ci.origin)) continue;
            count++;
            long rk = an.rank(e.getKey());
            if (rk < bestRank || (rk == bestRank && e.getKey().compareTo(best) < 0)) {
                bestRank = rk;
                best = e.getKey();
            }
        }
        pr.put("reachable", best != null);
        pr.put("reachable_strong", best != null && !an.weak.contains(best));
        pr.put("reachable_methods_in_package", count);
        if (best != null) pr.put("witness_path", an.path(best, maxPath));
        r.put("package", pr);

        // function-level: are the vulnerable methods reachable?
        List<Object> sinks = new ArrayList<>();
        boolean anyReach = false;
        boolean anyStrong = false;
        boolean allMissing = true;
        for (Object so : Json.arr(cve.get("sinks"))) {
            Map<String, Object> s = Json.obj(so);
            String cls = Json.str(s.get("class")).replace('.', '/');
            String name = Json.str(s.get("method"));
            String desc = Json.str(s.get("desc"));
            ClassInfo ci = idx.get(cls);
            boolean present = false;
            if (ci != null) {
                for (MethodInfo m : ci.methods.values()) {
                    if (m.name.equals(name) && (desc == null || m.desc.equals(desc))) present = true;
                }
            }
            if (present) allMissing = false;
            String hit = null;
            long hitRank = Long.MAX_VALUE;
            boolean classReached = false;
            for (Map.Entry<String, MRef> e : an.reached.entrySet()) {
                MRef m = e.getValue();
                if (!m.owner().equals(cls)) continue;
                classReached = true;
                if (!m.name().equals(name) || (desc != null && !m.desc().equals(desc))) continue;
                long rk = an.rank(e.getKey());
                if (rk < hitRank) {
                    hitRank = rk;
                    hit = e.getKey();
                }
            }
            Map<String, Object> sr = new LinkedHashMap<>();
            sr.put("sink", Json.str(s.get("class")) + "#" + name + (desc == null ? "" : desc));
            sr.put("present_in_jar", present);
            sr.put("class_reached", classReached);
            sr.put("reachable", hit != null);
            if (hit != null) {
                anyReach = true;
                boolean w = an.weak.contains(hit);
                if (!w) anyStrong = true;
                sr.put("weak_path_only", w);
                sr.put("path", an.path(hit, maxPath));
            }
            sinks.add(sr);
        }
        r.put("sink_reachable", anyReach);
        r.put("sink_reachable_strong", anyStrong);
        r.put("all_sinks_missing", allMissing && !sinks.isEmpty());
        r.put("sinks", sinks);
        return r;
    }
}
