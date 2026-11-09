package com.logssey.reach.analyzer;

import org.objectweb.asm.Opcodes;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whole-program call graph by Rapid Type Analysis (RTA), built on the fly from entry points.
 *
 * <ul>
 *   <li>static / special calls resolve directly;</li>
 *   <li>virtual / interface calls resolve only to classes seen instantiated ({@code new}) in reachable code;</li>
 *   <li>lambdas and method references (LambdaMetafactory) are assumed to be invoked;</li>
 *   <li>static initialisers run when a class is first used;</li>
 *   <li>JDK code is not analysed. When an instantiated class overrides a method declared by a JDK type
 *       (Runnable.run, Comparator.compare, Object.toString, ...) that override is assumed reachable,
 *       because the JDK may call it back.</li>
 * </ul>
 * Reflection, JNI and dynamic proxies are not modelled; this is why framework-driven entry points are
 * handled by entry-point seeding (phase 1/2) and by configuration rules outside this class.
 */
final class Analyzer {

    record Edge(String from, String kind, int line, int phase) {}

    record Site(String caller, String owner, String name, String desc, int line, String kind) {}

    private static final Set<String> OBJECT_CALLBACKS = Set.of(
            "toString()Ljava/lang/String;", "hashCode()I", "equals(Ljava/lang/Object;)Z",
            "clone()Ljava/lang/Object;", "finalize()V");

    private final ClassIndex idx;
    private final Code code;
    private final Map<String, Set<String>> superMemo = new HashMap<>();
    private final Set<String> instantiated = new HashSet<>();
    private final Map<String, List<String>> instantiatedBySuper = new HashMap<>();
    private final Map<String, List<Site>> sitesByOwner = new HashMap<>();
    private final Set<String> clinitDone = new HashSet<>();
    private final ArrayDeque<String> work = new ArrayDeque<>();
    final Map<String, MRef> reached = new HashMap<>(); // key -> ref (also the visited set)
    final Map<String, Edge> parent = new HashMap<>();
    /** Methods reached only through an assumption-heavy edge (Object.equals/hashCode/toString dispatch, JDK callback). */
    final Set<String> weak = new HashSet<>();
    private final Map<String, Integer> depthMemo = new HashMap<>();
    int phase = 1;
    int callSites;
    /**
     * Two-stage fixpoint: first only "strong" edges, then also the assumption-heavy ones
     * (Object.equals/hashCode/toString dispatch and JDK callbacks). Anything first reached in the
     * second stage is marked weak, so a strong path is always preferred when one exists.
     */
    private boolean allowWeak = false;
    private final List<Object[]> deferredCallbacks = new ArrayList<>(); // {cls, from, line}

    Analyzer(ClassIndex idx, Code code) {
        this.idx = idx;
        this.code = code;
    }

    int instantiatedCount() {
        return instantiated.size();
    }

    // ------------------------------------------------------------------ hierarchy

    /** The class itself plus all superclasses and superinterfaces (index first, then JDK headers). */
    Set<String> supertypes(String cls) {
        Set<String> s = superMemo.get(cls);
        if (s != null) return s;
        s = new LinkedHashSet<>();
        ArrayDeque<String> q = new ArrayDeque<>();
        q.add(cls);
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!s.add(c)) continue;
            ClassInfo ci = idx.info(c);
            if (ci == null) continue;
            if (ci.superName != null) q.add(ci.superName);
            for (String i : ci.interfaces) q.add(i);
        }
        superMemo.put(cls, s);
        return s;
    }

    boolean isSubtype(String cls, String sup) {
        return supertypes(cls).contains(sup);
    }

    // ------------------------------------------------------------------ resolution

    private MRef resolveVirtual(String cls, String name, String desc) {
        String nd = name + desc;
        for (String c = cls; c != null; ) {
            ClassInfo ci = idx.get(c);
            if (ci == null) break; // implementation would be in the JDK: not analysed
            MethodInfo m = ci.methods.get(nd);
            if (m != null && !m.isStatic()) {
                return m.isAbstract() ? null : m.ref();
            }
            c = ci.superName;
        }
        for (String itf : supertypes(cls)) { // default methods
            ClassInfo ii = idx.get(itf);
            if (ii == null || !ii.isInterface()) continue;
            MethodInfo m = ii.methods.get(nd);
            if (m != null && !m.isAbstract() && !m.isStatic() && !m.isPrivate()) return m.ref();
        }
        return null;
    }

    private MRef resolveDirect(String owner, String name, String desc) {
        String nd = name + desc;
        for (String c = owner; c != null; ) {
            ClassInfo ci = idx.get(c);
            if (ci == null) return null;
            MethodInfo m = ci.methods.get(nd);
            if (m != null) return m.hasBody() ? m.ref() : null;
            if (name.equals("<init>")) return null; // constructors are not inherited
            c = ci.superName;
        }
        return null;
    }

    // ------------------------------------------------------------------ worklist

    void reach(MRef target, String from, String kind, int line) {
        if (target == null) return;
        String key = target.key();
        if (reached.containsKey(key)) return;
        ClassInfo ci = idx.get(target.owner());
        if (ci == null) return;
        MethodInfo mi = ci.methods.get(target.name() + target.desc());
        if (mi == null || !mi.hasBody()) return;
        reached.put(key, target);
        parent.put(key, new Edge(from, kind, line, phase));
        if (kind.startsWith("jdk-callback") || kind.endsWith("(Object)") || (from != null && weak.contains(from))) weak.add(key);
        work.add(key);
    }

    void run() {
        while (!work.isEmpty()) {
            String key = work.poll();
            MRef m = reached.get(key);
            Code.Summary s = code.of(m.owner(), m.name() + m.desc());
            if (s != null) process(key, s);
        }
    }

    private void process(String caller, Code.Summary s) {
        for (Code.At n : s.news) {
            instantiate(n.value(), caller, n.line());
        }
        for (String owner : s.staticOwners) clinit(owner, caller, -1);
        for (Code.Inv v : s.invokes) {
            switch (v.op()) {
                case Opcodes.INVOKESTATIC -> reach(resolveDirect(v.owner(), v.name(), v.desc()), caller, "static", v.line());
                case Opcodes.INVOKESPECIAL -> reach(resolveDirect(v.owner(), v.name(), v.desc()), caller,
                        v.name().equals("<init>") ? "new" : "special", v.line());
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE ->
                        addSite(new Site(caller, v.owner(), v.name(), v.desc(), v.line(),
                                v.owner().equals("java/lang/Object") ? "virtual(Object)" : "virtual"));
                default -> { }
            }
        }
        for (Code.Lam l : s.lambdas) {
            switch (l.tag()) {
                case Opcodes.H_INVOKESTATIC, Opcodes.H_INVOKESPECIAL ->
                        reach(resolveDirect(l.owner(), l.name(), l.desc()), caller, "lambda", l.line());
                case Opcodes.H_NEWINVOKESPECIAL -> {
                    instantiate(l.owner(), caller, l.line());
                    reach(resolveDirect(l.owner(), l.name(), l.desc()), caller, "lambda-new", l.line());
                }
                case Opcodes.H_INVOKEVIRTUAL, Opcodes.H_INVOKEINTERFACE ->
                        addSite(new Site(caller, l.owner(), l.name(), l.desc(), l.line(), "method-ref"));
                default -> { }
            }
        }
    }

    private void addSite(Site site) {
        callSites++;
        sitesByOwner.computeIfAbsent(site.owner(), k -> new ArrayList<>()).add(site);
        List<String> subs = instantiatedBySuper.get(site.owner());
        if (subs != null) {
            for (int k = 0; k < subs.size(); k++) dispatch(subs.get(k), site);
        }
    }

    private void dispatch(String cls, Site site) {
        if (!allowWeak && site.kind().endsWith("(Object)")) return; // replayed by enableWeakEdges()
        reach(resolveVirtual(cls, site.name(), site.desc()), site.caller(), site.kind(), site.line());
    }

    /** Second stage: replay the deferred Object-dispatch sites and JDK callbacks, then run to fixpoint. */
    void enableWeakEdges() {
        allowWeak = true;
        List<Site> objectSites = sitesByOwner.getOrDefault("java/lang/Object", List.of());
        List<String> all = instantiatedBySuper.getOrDefault("java/lang/Object", List.of());
        for (int i = 0; i < objectSites.size(); i++) {
            for (int k = 0; k < all.size(); k++) dispatch(all.get(k), objectSites.get(i));
        }
        for (Object[] d : deferredCallbacks) jdkCallbacks((String) d[0], (String) d[1], (Integer) d[2]);
        deferredCallbacks.clear();
        run();
    }

    void instantiate(String cls, String from, int line) {
        if (!instantiated.add(cls)) return;
        ClassInfo ci = idx.get(cls);
        if (ci == null) return; // JDK or missing class: its code is not analysed
        clinit(cls, from, line);
        for (String sup : supertypes(cls)) {
            instantiatedBySuper.computeIfAbsent(sup, k -> new ArrayList<>()).add(cls);
            List<Site> sites = sitesByOwner.get(sup);
            if (sites != null) {
                for (int k = 0; k < sites.size(); k++) dispatch(cls, sites.get(k));
            }
        }
        jdkCallbacks(cls, from, line);
    }

    /** Overrides of JDK-declared methods may be called back by the JDK (Runnable.run, compare, toString...). */
    private void jdkCallbacks(String cls, String from, int line) {
        if (!allowWeak) {
            deferredCallbacks.add(new Object[] {cls, from, line});
            return;
        }
        for (String sup : supertypes(cls)) {
            if (idx.get(sup) != null) continue;
            ClassInfo ext = idx.info(sup);
            if (ext == null) continue;
            for (MethodInfo m : ext.methods.values()) {
                if (m.isStatic() || m.isPrivate() || m.name.startsWith("<")) continue;
                if (sup.equals("java/lang/Object") && !OBJECT_CALLBACKS.contains(m.name + m.desc)) continue;
                MRef t = resolveVirtual(cls, m.name, m.desc);
                if (t != null) reach(t, from, "jdk-callback:" + sup.substring(sup.lastIndexOf('/') + 1), line);
            }
        }
    }

    private void clinit(String cls, String from, int line) {
        for (String c = cls; c != null; ) {
            if (!clinitDone.add(c)) return;
            ClassInfo ci = idx.get(c);
            if (ci == null) return;
            MethodInfo m = ci.methods.get("<clinit>()V");
            if (m != null) reach(m.ref(), from, "static-init", line);
            c = ci.superName;
        }
    }

    // ------------------------------------------------------------------ paths

    /** Ranking key for choosing the most convincing path: strong paths first, then shorter. */
    long rank(String key) {
        return (weak.contains(key) ? 1_000_000L : 0L) + depth(key);
    }

    int depth(String key) {
        Integer d = depthMemo.get(key);
        if (d != null) return d;
        int n = 0;
        String k = key;
        while (k != null && n < 10_000) {
            Edge e = parent.get(k);
            if (e == null || e.from() == null) break;
            k = e.from();
            n++;
        }
        depthMemo.put(key, n);
        return n;
    }

    /** Path from an entry point to the given method, as a list of steps (entry first). */
    List<Map<String, Object>> path(String key, int maxSteps) {
        List<String> keys = new ArrayList<>();
        String k = key;
        Set<String> seen = new HashSet<>();
        while (k != null && seen.add(k)) {
            keys.add(k);
            Edge e = parent.get(k);
            k = e == null ? null : e.from();
        }
        java.util.Collections.reverse(keys);
        List<Map<String, Object>> out = new ArrayList<>();
        int skip = Math.max(0, keys.size() - maxSteps);
        for (int i = 0; i < keys.size(); i++) {
            if (skip > 0 && i == 1) {
                out.add(Map.of("note", "... " + skip + " steps omitted ..."));
                i += skip - 1;
                continue;
            }
            String key2 = keys.get(i);
            MRef r = reached.get(key2);
            Edge e = parent.get(key2);
            ClassInfo ci = idx.get(r.owner());
            Map<String, Object> step = new java.util.LinkedHashMap<>();
            step.put("method", r.pretty());
            step.put("short", r.shortName());
            step.put("in", ci == null ? "?" : ci.origin);
            step.put("via", e == null ? "?" : e.kind());
            if (e != null && e.line() > 0) step.put("called_at_line", e.line());
            out.add(step);
        }
        return out;
    }
}
