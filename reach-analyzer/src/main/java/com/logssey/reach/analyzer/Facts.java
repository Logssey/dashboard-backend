package com.logssey.reach.analyzer;

import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Collects configuration-level facts from first-party (app) classes only, as defined in rules.json:
 * calls, instantiations, string constants, annotations, type references, and properties of the
 * types that are deserialised from untrusted input ("DTO roots").
 */
final class Facts {
    private final ClassIndex idx;
    private final Code code;
    private final Analyzer an;
    private final Map<String, Object> rules;
    final Map<String, List<Map<String, Object>>> found = new LinkedHashMap<>();
    final List<Map<String, Object>> roots = new ArrayList<>();
    private final List<String[]> rootTypes = new ArrayList<>(); // {label, internal name}
    /** Types named anywhere Jackson could be told about them (class literal, TypeReference, ...). Superset of rootTypes. */
    private final List<String[]> tokenTypes = new ArrayList<>(); // {label, internal name}

    Facts(ClassIndex idx, Code code, Analyzer an, Map<String, Object> rules) {
        this.idx = idx;
        this.code = code;
        this.an = an;
        this.rules = rules;
    }

    private void add(String id, String where, String detail) {
        List<Map<String, Object>> l = found.computeIfAbsent(id, k -> new ArrayList<>());
        if (l.size() >= 50) return;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("where", where);
        if (detail != null) m.put("detail", detail);
        if (!l.contains(m)) l.add(m);
    }

    private static String simple(String internal) {
        String s = internal.substring(internal.lastIndexOf('/') + 1);
        return s;
    }

    private static String where(ClassInfo c, MethodInfo m, int line) {
        String w = c.name.replace('/', '.') + "#" + m.name;
        return line > 0 ? w + ":" + line : w;
    }

    private boolean ownerMatches(String owner, List<String> owners, List<String> prefixes, boolean subtypes) {
        for (String p : prefixes) if (owner.startsWith(p)) return true;
        for (String o : owners) {
            if (owner.equals(o)) return true;
            if (subtypes && an.isSubtype(owner, o)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ main

    void collect() {
        computeRoots();
        computeTokens();
        List<Object> defs = Json.arr(rules.get("facts"));
        List<ClassInfo> app = new ArrayList<>();
        for (ClassInfo c : idx.classes.values()) if (c.app) app.add(c);
        app.sort((a, b) -> a.name.compareTo(b.name));
        for (Object o : defs) {
            Map<String, Object> d = Json.obj(o);
            String id = Json.str(d.get("id"));
            String type = Json.str(d.get("type"));
            found.putIfAbsent(id, new ArrayList<>());
            switch (type) {
                case "call" -> calls(id, d, app);
                case "new" -> news(id, d, app);
                case "extends" -> extendsFact(id, d, app);
                case "ldc" -> ldc(id, d, app);
                case "annotation" -> annotations(id, d, app);
                case "param-annotation" -> paramAnnotations(id, d, app);
                case "type-ref" -> typeRefs(id, d, app);
                case "jar" -> jars(id, d);
                case "dto-field-type", "dto-annotation", "dto-collection-element-annotation" -> dto(id, type, d, app);
                default -> idx.warnings.add("unknown fact type " + type + " for " + id);
            }
        }
    }

    private void calls(String id, Map<String, Object> d, List<ClassInfo> app) {
        List<String> owners = Json.strs(d.get("owners"));
        List<String> prefixes = Json.strs(d.get("owner_prefixes"));
        List<String> names = Json.strs(d.get("names"));
        String descContains = Json.str(d.get("desc_contains"));
        boolean subtypes = !Boolean.FALSE.equals(d.get("subtypes"));
        for (ClassInfo c : app) {
            Map<String, Code.Summary> ms = code.forClass(c.name);
            if (ms == null) continue;
            for (MethodInfo m : c.methods.values()) {
                Code.Summary s = ms.get(m.name + m.desc);
                if (s == null) continue;
                for (Code.Inv v : s.invokes) {
                    if (!names.isEmpty() && !names.contains(v.name())) continue;
                    if (descContains != null && !v.desc().contains(descContains)) continue;
                    if (!ownerMatches(v.owner(), owners, prefixes, subtypes)) continue;
                    add(id, where(c, m, v.line()), v.owner().replace('/', '.') + "." + v.name() + v.desc());
                }
            }
        }
    }

    private void news(String id, Map<String, Object> d, List<ClassInfo> app) {
        List<String> classes = Json.strs(d.get("classes"));
        boolean subtypes = !Boolean.FALSE.equals(d.get("subtypes"));
        for (ClassInfo c : app) {
            Map<String, Code.Summary> ms = code.forClass(c.name);
            if (ms == null) continue;
            for (MethodInfo m : c.methods.values()) {
                Code.Summary s = ms.get(m.name + m.desc);
                if (s == null) continue;
                for (Code.At n : s.news) {
                    if (ownerMatches(n.value(), classes, List.of(), subtypes)) {
                        add(id, where(c, m, n.line()), "new " + n.value().replace('/', '.'));
                    }
                }
            }
        }
    }

    private void extendsFact(String id, Map<String, Object> d, List<ClassInfo> app) {
        List<String> classes = Json.strs(d.get("classes"));
        for (ClassInfo c : app) {
            for (String sup : an.supertypes(c.name)) {
                if (!sup.equals(c.name) && classes.contains(sup)) add(id, c.name.replace('/', '.'), "extends/implements " + sup.replace('/', '.'));
            }
        }
    }

    private void ldc(String id, Map<String, Object> d, List<ClassInfo> app) {
        Pattern p = Pattern.compile(Json.str(d.get("regex")));
        for (ClassInfo c : app) {
            Map<String, Code.Summary> ms = code.forClass(c.name);
            if (ms == null) continue;
            for (MethodInfo m : c.methods.values()) {
                Code.Summary s = ms.get(m.name + m.desc);
                if (s == null) continue;
                for (Code.At a : s.ldcStrings) {
                    if (p.matcher(a.value()).find()) add(id, where(c, m, a.line()), "\"" + a.value() + "\"");
                }
            }
        }
    }

    private void annotations(String id, Map<String, Object> d, List<ClassInfo> app) {
        Set<String> anns = new HashSet<>(Json.strs(d.get("annotations")));
        for (ClassInfo c : app) {
            for (Ann a : c.anns) if (anns.contains(a.desc)) add(id, c.name.replace('/', '.'), "@" + simple(Type.getType(a.desc).getInternalName()) + " on class");
            for (FieldInfo f : c.fields) {
                for (Ann a : f.anns) if (anns.contains(a.desc)) add(id, c.name.replace('/', '.') + "." + f.name, "@" + simple(Type.getType(a.desc).getInternalName()) + " on field");
            }
            for (MethodInfo m : c.methods.values()) {
                for (Ann a : m.anns) if (anns.contains(a.desc)) add(id, where(c, m, -1), "@" + simple(Type.getType(a.desc).getInternalName()) + " on method");
                for (List<Ann> l : m.paramAnns.values()) {
                    for (Ann a : l) if (anns.contains(a.desc)) add(id, where(c, m, -1), "@" + simple(Type.getType(a.desc).getInternalName()) + " on parameter");
                }
            }
        }
    }

    private void paramAnnotations(String id, Map<String, Object> d, List<ClassInfo> app) {
        Set<String> anns = new HashSet<>(Json.strs(d.get("annotations")));
        for (ClassInfo c : app) {
            for (MethodInfo m : c.methods.values()) {
                Type[] args = Type.getArgumentTypes(m.desc);
                for (int i = 0; i < args.length; i++) {
                    for (Ann a : m.annsOfParam(i)) {
                        if (anns.contains(a.desc)) {
                            add(id, where(c, m, -1), "@" + simple(Type.getType(a.desc).getInternalName()) + " " + args[i].getClassName());
                        }
                    }
                }
            }
        }
    }

    private void typeRefs(String id, Map<String, Object> d, List<ClassInfo> app) {
        Set<String> types = new HashSet<>(Json.strs(d.get("types")));
        for (ClassInfo c : app) {
            for (FieldInfo f : c.fields) {
                for (String t : typesIn(f.desc, f.signature)) if (types.contains(t)) add(id, c.name.replace('/', '.') + "." + f.name, "field type " + t.replace('/', '.'));
            }
            Map<String, Code.Summary> ms = code.forClass(c.name);
            for (MethodInfo m : c.methods.values()) {
                for (String t : typesIn(m.desc, m.signature)) if (types.contains(t)) add(id, where(c, m, -1), "signature uses " + t.replace('/', '.'));
                Code.Summary s = ms == null ? null : ms.get(m.name + m.desc);
                if (s == null) continue;
                for (Code.At a : s.typeRefs) if (types.contains(a.value())) add(id, where(c, m, a.line()), "code references " + a.value().replace('/', '.'));
                for (Code.At a : s.news) if (types.contains(a.value())) add(id, where(c, m, a.line()), "new " + a.value().replace('/', '.'));
                for (Code.Inv v : s.invokes) if (types.contains(v.owner())) add(id, where(c, m, v.line()), "calls " + v.owner().replace('/', '.') + "." + v.name());
            }
        }
    }

    private void jars(String id, Map<String, Object> d) {
        Pattern p = Pattern.compile(Json.str(d.get("regex")));
        for (String jar : idx.jarClassCount.keySet()) if (p.matcher(jar).find()) add(id, jar, "bundled library");
    }

    // ------------------------------------------------------------------ types in descriptors/signatures

    /** All class (internal) names that appear in a descriptor and its generic signature. */
    static List<String> typesIn(String desc, String signature) {
        List<String> out = new ArrayList<>();
        if (signature != null) {
            try {
                new SignatureReader(signature).accept(new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) {
                    @Override
                    public void visitClassType(String name) {
                        out.add(name);
                    }

                    @Override
                    public void visitInnerClassType(String name) {
                        if (!out.isEmpty()) out.set(out.size() - 1, out.get(out.size() - 1) + "$" + name);
                    }
                });
            } catch (RuntimeException ignored) {
                // malformed signature: fall back to descriptor
            }
        }
        if (desc != null) {
            Type t = Type.getType(desc);
            if (t.getSort() == Type.METHOD) {
                for (Type a : t.getArgumentTypes()) addType(out, a);
                addType(out, t.getReturnType());
            } else {
                addType(out, t);
            }
        }
        return out;
    }

    private static void addType(List<String> out, Type t) {
        while (t.getSort() == Type.ARRAY) t = t.getElementType();
        if (t.getSort() == Type.OBJECT && !out.contains(t.getInternalName())) out.add(t.getInternalName());
    }

    /** Descriptor-style tokens for a field: primitive descriptors (e.g. "D") plus "Lx/y/Z;" for each class type. */
    private static List<String> fieldTokens(FieldInfo f) {
        List<String> tokens = new ArrayList<>();
        Type t = Type.getType(f.desc);
        while (t.getSort() == Type.ARRAY) t = t.getElementType();
        if (t.getSort() != Type.OBJECT) tokens.add(t.getDescriptor());
        for (String n : typesIn(f.desc, f.signature)) tokens.add("L" + n + ";");
        return tokens;
    }

    // ------------------------------------------------------------------ DTO roots

    private void root(String label, String type) {
        if (type == null) return;
        rootTypes.add(new String[] {label, type});
    }

    private void computeRoots() {
        Map<String, Object> cfg = Json.obj(rules.get("dto_roots"));
        Set<String> paramAnns = new HashSet<>(Json.strs(cfg.get("param_annotations")));
        Set<String> listenerAnns = new HashSet<>(Json.strs(cfg.get("listener_method_annotations")));
        Set<String> bodyTypes = new HashSet<>(Json.strs(cfg.get("body_param_types")));
        Set<String> clientAnns = new HashSet<>(Json.strs(cfg.get("client_annotations")));
        Set<String> typeRefClasses = new HashSet<>(Json.strs(cfg.get("type_reference_classes")));
        List<Object> deser = Json.arr(cfg.get("deserializer_calls"));

        for (ClassInfo c : idx.classes.values()) {
            if (!c.app) continue;
            boolean clientIface = c.isInterface() && c.anns.stream().anyMatch(a -> clientAnns.contains(a.desc));
            for (MethodInfo m : c.methods.values()) {
                Type[] args = Type.getArgumentTypes(m.desc);
                Params params = paramTypes(m, args.length);
                boolean listener = m.anns.stream().anyMatch(a -> listenerAnns.contains(a.desc));
                for (int i = 0; i < args.length; i++) {
                    boolean annotated = m.annsOfParam(i).stream().anyMatch(a -> paramAnns.contains(a.desc));
                    List<String> pts = params.classes().get(i);
                    if (pts.isEmpty() && !params.vars().get(i).isEmpty()) {
                        pts = new ArrayList<>(); // a bare type variable: keep its erasure (Object or the bound)
                        addType(pts, args[i]);
                    }
                    boolean body = !pts.isEmpty() && bodyTypes.contains(pts.get(0));
                    if (annotated || listener || body) {
                        String kind = annotated ? "@body " : listener ? "@listener " : "";
                        String label = simple(c.name) + "." + m.name + "(" + kind + "param " + i + ")";
                        roots.add(Map.of("root", label, "types", pts));
                        for (String t : pts) root(label, t);
                        // create(@RequestBody T body) in CrudController<T>: the framework reads the body as the
                        // type argument each subtype gives (ItemController extends CrudController<ItemRequest>)
                        for (String var : params.vars().get(i)) {
                            if (params.methodVars().contains(var)) continue;
                            for (Map.Entry<String, List<String>> b : boundTypes(c, var).entrySet()) {
                                String sub = simple(b.getKey()) + "." + m.name + "(" + kind + "param " + i + ", "
                                        + var + " of " + simple(c.name) + ")";
                                roots.add(Map.of("root", sub, "types", b.getValue()));
                                for (String t : b.getValue()) root(sub, t);
                            }
                        }
                    }
                }
                boolean clientMethod = clientIface || m.anns.stream().anyMatch(a -> clientAnns.contains(a.desc));
                if (clientMethod && !m.isStatic()) {
                    List<String> rts = returnTypes(m);
                    String label = simple(c.name) + "." + m.name + "(client response)";
                    roots.add(Map.of("root", label, "types", rts));
                    for (String t : rts) root(label, t);
                }
            }
            Map<String, Code.Summary> ms = null;
            for (MethodInfo m : c.methods.values()) {
                if (ms == null) ms = code.forClass(c.name);
                if (ms == null) break;
                Code.Summary s = ms.get(m.name + m.desc);
                if (s == null) continue;
                boolean callsDeser = false;
                for (Code.Inv v : s.invokes) {
                    for (Object o : deser) {
                        Map<String, Object> dc = Json.obj(o);
                        if (Json.strs(dc.get("names")).contains(v.name())
                                && ownerMatches(v.owner(), Json.strs(dc.get("owners")), Json.strs(dc.get("owner_prefixes")), true)) {
                            callsDeser = true;
                        }
                    }
                }
                if (!callsDeser) continue;
                String label = simple(c.name) + "." + m.name + "(deserialize call)";
                List<String> ts = new ArrayList<>();
                for (Code.At lit : s.classLiterals) ts.add(lit.value());
                for (Code.At n : s.news) { // anonymous TypeReference<...> subclasses
                    ClassInfo anon = idx.get(n.value());
                    if (anon != null && anon.superName != null && typeRefClasses.contains(anon.superName) && anon.signature != null) {
                        for (String t : typesIn(null, anon.signature)) if (!typeRefClasses.contains(t)) ts.add(t);
                    }
                }
                if (!ts.isEmpty()) {
                    roots.add(Map.of("root", label, "types", ts));
                    for (String t : ts) root(label, t);
                }
            }
        }
    }

    /**
     * Jackson only deserialises into a type someone names: a root, a class literal handed around before it reaches
     * readValue, a TypeReference, a Jackson annotation value (@JsonDeserialize(as=...), @JsonSubTypes), or a method
     * signature a framework reads (@Cacheable return type). A type that appears in none of these (e.g. a response
     * record built with {@code new} and returned) is never a deserialisation target. Polymorphic typing (@class type
     * ids) can name any type and is checked by separate facts.
     */
    private void computeTokens() {
        Map<String, Object> cfg = Json.obj(rules.get("dto_roots"));
        Set<String> typeRefClasses = new HashSet<>(Json.strs(cfg.get("type_reference_classes")));
        List<String> annPrefixes = Json.strs(cfg.get("type_token_annotation_prefixes"));
        Set<String> sigAnns = new HashSet<>(Json.strs(cfg.get("signature_type_annotations")));
        tokenTypes.addAll(rootTypes);

        for (ClassInfo c : idx.classes.values()) {
            if (!c.app) continue;
            tokenAnns(simple(c.name), c.anns, annPrefixes);
            for (FieldInfo f : c.fields) tokenAnns(simple(c.name) + "." + f.name, f.anns, annPrefixes);
            Map<String, Code.Summary> ms = code.forClass(c.name);
            for (MethodInfo m : c.methods.values()) {
                String label = simple(c.name) + "." + m.name;
                tokenAnns(label, m.anns, annPrefixes);
                if (m.anns.stream().anyMatch(a -> sigAnns.contains(a.desc))) {
                    for (String t : returnTypes(m)) tokenTypes.add(new String[] {label + "(return type)", t});
                }
                Code.Summary s = ms == null ? null : ms.get(m.name + m.desc);
                if (s == null) continue;
                for (Code.At lit : s.classLiterals) tokenTypes.add(new String[] {label + ":" + lit.line() + "(class literal)", lit.value()});
                for (Code.At n : s.news) {
                    ClassInfo anon = idx.get(n.value());
                    if (anon != null && anon.superName != null && typeRefClasses.contains(anon.superName) && anon.signature != null) {
                        for (String t : typesIn(null, anon.signature)) {
                            if (!typeRefClasses.contains(t)) tokenTypes.add(new String[] {label + ":" + n.line() + "(type reference)", t});
                        }
                    }
                }
            }
        }
    }

    /** App types among the type tokens (library types such as String.class are never DTOs), for the result file. */
    List<Map<String, Object>> typeTokens() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String[] t : tokenTypes) {
            ClassInfo ci = idx.get(t[1]);
            if (ci == null || !ci.app) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("where", t[0]);
            m.put("type", t[1].replace('/', '.'));
            if (!out.contains(m)) out.add(m);
        }
        return out;
    }

    private void tokenAnns(String label, List<Ann> anns, List<String> prefixes) {
        for (Ann a : anns) {
            if (prefixes.stream().noneMatch(a.desc::startsWith)) continue;
            List<String> ts = new ArrayList<>();
            classValues(a.values.values(), ts);
            String where = label + "(@" + simple(Type.getType(a.desc).getInternalName()) + ")";
            for (String t : ts) tokenTypes.add(new String[] {where, t});
        }
    }

    /** Class-valued annotation elements (AnnCollector stores them as descriptors), including nested ones. */
    private static void classValues(Iterable<?> values, List<String> out) {
        for (Object v : values) {
            if (v instanceof String s && s.startsWith("L") && s.endsWith(";") && s.indexOf(' ') < 0) {
                out.add(s.substring(1, s.length() - 1));
            } else if (v instanceof List<?> l) {
                classValues(l, out);
            } else if (v instanceof Map<?, ?> m) {
                classValues(m.values(), out);
            }
        }
    }

    /**
     * Types of each parameter, from the generic signature when there is one: the class names used, the type
     * variables used, and the type variables the method itself declares (&lt;T&gt; void m(T body)).
     */
    private record Params(List<List<String>> classes, List<List<String>> vars, Set<String> methodVars) {}

    private static Params paramTypes(MethodInfo m, int argc) {
        List<List<String>> out = new ArrayList<>();
        List<List<String>> vars = new ArrayList<>();
        Set<String> methodVars = new HashSet<>();
        for (int i = 0; i < argc; i++) {
            out.add(new ArrayList<>());
            vars.add(new ArrayList<>());
        }
        if (m.signature != null) {
            try {
                int[] cur = {-1};
                new SignatureReader(m.signature).accept(new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) {
                    @Override
                    public void visitFormalTypeParameter(String name) {
                        methodVars.add(name);
                    }

                    @Override
                    public SignatureVisitor visitParameterType() {
                        cur[0]++;
                        return this;
                    }

                    @Override
                    public SignatureVisitor visitReturnType() {
                        cur[0] = Integer.MAX_VALUE;
                        return this;
                    }

                    @Override
                    public SignatureVisitor visitExceptionType() {
                        cur[0] = Integer.MAX_VALUE;
                        return this;
                    }

                    @Override
                    public void visitClassType(String name) {
                        if (cur[0] >= 0 && cur[0] < argc) out.get(cur[0]).add(name);
                    }

                    @Override
                    public void visitTypeVariable(String name) {
                        if (cur[0] >= 0 && cur[0] < argc) vars.get(cur[0]).add(name);
                    }
                });
                boolean any = out.stream().anyMatch(l -> !l.isEmpty()) || vars.stream().anyMatch(l -> !l.isEmpty());
                if (any) return new Params(out, vars, methodVars);
            } catch (RuntimeException ignored) {
                // fall through
            }
            for (List<String> l : out) l.clear();
            for (List<String> l : vars) l.clear();
            methodVars.clear();
        }
        Type[] args = Type.getArgumentTypes(m.desc);
        for (int i = 0; i < argc; i++) addType(out.get(i), args[i]);
        return new Params(out, vars, methodVars);
    }

    // ------------------------------------------------------------------ type arguments given by subtypes

    /** One type argument as written in a signature: the class names in it and the type variables in it. */
    private record Arg(List<String> classes, List<String> vars) {}

    /** A supertype as written in a class signature (extends CrudController&lt;ItemRequest&gt;). */
    private record Super(String name, List<Arg> args) {}

    private static final class ClassSig {
        final List<String> formals = new ArrayList<>(); // type parameter names, in order
        final List<Super> supers = new ArrayList<>();
    }

    private final Map<String, ClassSig> classSigs = new HashMap<>();

    private ClassSig classSig(ClassInfo c) {
        ClassSig cached = classSigs.get(c.name);
        if (cached != null) return cached;
        ClassSig out = new ClassSig();
        boolean parsed = false;
        if (c.signature != null) {
            try {
                new SignatureReader(c.signature).accept(new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) {
                    @Override
                    public void visitFormalTypeParameter(String name) {
                        out.formals.add(name);
                    }

                    @Override
                    public SignatureVisitor visitSuperclass() {
                        return superType(out);
                    }

                    @Override
                    public SignatureVisitor visitInterface() {
                        return superType(out);
                    }
                });
                parsed = true;
            } catch (RuntimeException ignored) {
                out.formals.clear();
                out.supers.clear();
            }
        }
        if (!parsed) { // no generic signature: the supertypes carry no type arguments
            if (c.superName != null) out.supers.add(new Super(c.superName, List.of()));
            for (String i : c.interfaces) out.supers.add(new Super(i, List.of()));
        }
        classSigs.put(c.name, out);
        return out;
    }

    private static SignatureVisitor superType(ClassSig out) {
        String[] name = {null};
        List<Arg> args = new ArrayList<>();
        return new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public void visitClassType(String n) {
                name[0] = n;
            }

            @Override
            public void visitInnerClassType(String n) {
                name[0] = name[0] + "$" + n;
                args.clear();
            }

            @Override
            public void visitTypeArgument() {
                args.add(new Arg(List.of(), List.of())); // unbounded wildcard
            }

            @Override
            public SignatureVisitor visitTypeArgument(char wildcard) {
                Arg arg = new Arg(new ArrayList<>(), new ArrayList<>());
                args.add(arg);
                return new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) { // nested arguments land in the same Arg
                    @Override
                    public void visitClassType(String n) {
                        arg.classes().add(n);
                    }

                    @Override
                    public void visitTypeVariable(String n) {
                        arg.vars().add(n);
                    }
                };
            }

            @Override
            public void visitEnd() {
                if (name[0] != null) out.supers.add(new Super(name[0], args));
            }
        };
    }

    /**
     * How sub fills the type parameters of target (parameter name to argument), following extends and implements
     * through intermediate generic types. Null when sub is not a subtype of target.
     */
    private Map<String, Arg> bind(ClassInfo sub, String target, Set<String> seen) {
        if (!seen.add(sub.name)) return null;
        for (Super s : classSig(sub).supers) {
            ClassInfo sc = idx.get(s.name());
            if (sc == null) continue;
            Map<String, Arg> inner; // target's parameters written with sc's own parameters
            if (s.name().equals(target)) {
                inner = new LinkedHashMap<>();
                for (String f : classSig(sc).formals) inner.put(f, new Arg(List.of(), List.of(f)));
            } else {
                inner = bind(sc, target, seen);
                if (inner == null) continue;
            }
            List<String> formals = classSig(sc).formals;
            Map<String, Arg> given = new HashMap<>(); // sc's parameters as sub fills them
            for (int i = 0; i < formals.size() && i < s.args().size(); i++) given.put(formals.get(i), s.args().get(i));
            Map<String, Arg> result = new LinkedHashMap<>();
            for (Map.Entry<String, Arg> e : inner.entrySet()) {
                List<String> classes = new ArrayList<>(e.getValue().classes());
                List<String> vars = new ArrayList<>();
                for (String v : e.getValue().vars()) {
                    Arg a = given.get(v);
                    if (a == null) continue; // raw supertype: nothing is known
                    classes.addAll(a.classes());
                    vars.addAll(a.vars());
                }
                result.put(e.getKey(), new Arg(classes, vars));
            }
            return result;
        }
        return null;
    }

    /** App subtype name to the class types it gives for the type parameter var of generic. Subtypes that leave it open are left out. */
    private Map<String, List<String>> boundTypes(ClassInfo generic, String var) {
        Map<String, List<String>> out = new TreeMap<>();
        if (!classSig(generic).formals.contains(var)) return out;
        for (ClassInfo sub : idx.classes.values()) {
            if (!sub.app || sub == generic) continue;
            Map<String, Arg> bound = bind(sub, generic.name, new HashSet<>());
            if (bound == null) continue;
            Arg a = bound.get(var);
            if (a != null && !a.classes().isEmpty()) out.put(sub.name, a.classes());
        }
        return out;
    }

    private static List<String> returnTypes(MethodInfo m) {
        List<String> out = new ArrayList<>();
        if (m.signature != null) {
            try {
                boolean[] inReturn = {false};
                new SignatureReader(m.signature).accept(new SignatureVisitor(org.objectweb.asm.Opcodes.ASM9) {
                    @Override
                    public SignatureVisitor visitReturnType() {
                        inReturn[0] = true;
                        return this;
                    }

                    @Override
                    public SignatureVisitor visitParameterType() {
                        inReturn[0] = false;
                        return this;
                    }

                    @Override
                    public SignatureVisitor visitExceptionType() {
                        inReturn[0] = false;
                        return this;
                    }

                    @Override
                    public void visitClassType(String name) {
                        if (inReturn[0]) out.add(name);
                    }
                });
            } catch (RuntimeException ignored) {
                out.clear();
            }
        }
        if (out.isEmpty()) addType(out, Type.getReturnType(m.desc));
        return out;
    }

    // ------------------------------------------------------------------ DTO graph facts

    private void dto(String id, String type, Map<String, Object> d, List<ClassInfo> app) {
        String scope = d.get("scope") == null ? "roots" : Json.str(d.get("scope"));
        Set<String> wanted = new HashSet<>(Json.strs("dto-field-type".equals(type) ? d.get("types") : d.get("annotations")));
        String requireAttr = Json.str(d.get("require_attr"));
        List<String[]> starts = new ArrayList<>();
        if ("all".equals(scope)) {
            for (ClassInfo c : app) starts.add(new String[] {simple(c.name), c.name});
        } else if ("tokens".equals(scope)) {
            starts.addAll(tokenTypes);
        } else {
            starts.addAll(rootTypes);
        }
        if ("dto-collection-element-annotation".equals(type) && "roots".equals(scope)) rootContainerElements(id, wanted);
        Set<String> visited = new HashSet<>();
        ArrayDeque<String[]> q = new ArrayDeque<>(); // {type, path}
        for (String[] s : starts) {
            // a root type itself may match (e.g. @RequestBody BigDecimal amount)
            if ("dto-field-type".equals(type) && wanted.contains("L" + s[1] + ";")) add(id, s[0], "root type " + s[1].replace('/', '.'));
            q.add(new String[] {s[1], s[0]});
        }
        while (!q.isEmpty()) {
            String[] cur = q.poll();
            String t = cur[0];
            ClassInfo ci = idx.get(t);
            if (ci == null || !ci.app || !visited.add(t)) continue;
            String path = cur[1];
            // dto-collection-element-annotation: an annotated type matters only as a collection/map element,
            // which the field loop below and rootContainerElements() check; the type on its own does not count
            if ("dto-annotation".equals(type)) {
                for (Ann a : ci.anns) if (wanted.contains(a.desc) && attrOk(a, requireAttr)) add(id, path, "@" + simple(Type.getType(a.desc).getInternalName()) + " on type " + simple(t));
            }
            if (ci.superName != null && idx.get(ci.superName) != null && idx.get(ci.superName).app) {
                q.add(new String[] {ci.superName, path + " (super " + simple(ci.superName) + ")"});
            }
            for (FieldInfo f : ci.fields) {
                if (f.isStatic()) continue;
                String fpath = path + " → " + simple(t) + "." + f.name;
                List<String> fieldTypes = typesIn(f.desc, f.signature);
                switch (type) {
                    case "dto-field-type" -> {
                        for (String tok : fieldTokens(f)) if (wanted.contains(tok)) add(id, fpath, "field type " + Type.getType(tok).getClassName());
                    }
                    case "dto-annotation" -> {
                        for (Ann a : f.anns) if (wanted.contains(a.desc) && attrOk(a, requireAttr)) add(id, fpath, "@" + simple(Type.getType(a.desc).getInternalName()) + " on field");
                    }
                    case "dto-collection-element-annotation" -> {
                        if (isContainer(f)) {
                            for (Ann a : f.anns) if (wanted.contains(a.desc)) add(id, fpath, "@" + simple(Type.getType(a.desc).getInternalName()) + " on collection field");
                            for (String et : fieldTypes) {
                                ClassInfo ec = idx.get(et);
                                if (ec == null || !ec.app) continue;
                                for (Ann a : ec.anns) if (wanted.contains(a.desc)) add(id, fpath, "element type " + simple(et) + " has @" + simple(Type.getType(a.desc).getInternalName()));
                            }
                        }
                    }
                    default -> { }
                }
                for (String ft : fieldTypes) {
                    ClassInfo fc = idx.get(ft);
                    if (fc != null && fc.app && !visited.contains(ft)) q.add(new String[] {ft, fpath});
                }
            }
        }
    }

    private static boolean attrOk(Ann a, String requireAttr) {
        return requireAttr == null || a.values.containsKey(requireAttr);
    }

    /**
     * A root that is itself a collection/map (@RequestBody List&lt;Node&gt;, TypeReference&lt;Map&lt;String, Node&gt;&gt;) with an
     * annotated element type. A root's types are flattened, so any container plus any annotated app type in the same
     * root counts (conservative). A root that is only the annotated type (readValue(json, Node.class)) does not.
     */
    private void rootContainerElements(String id, Set<String> wanted) {
        for (Map<String, Object> r : roots) {
            List<String> ts = Json.strs(r.get("types"));
            boolean container = ts.stream().anyMatch(t -> an.isSubtype(t, "java/util/Collection") || an.isSubtype(t, "java/util/Map"));
            if (!container) continue;
            for (String et : ts) {
                ClassInfo ec = idx.get(et);
                if (ec == null || !ec.app) continue;
                for (Ann a : ec.anns) if (wanted.contains(a.desc)) add(id, Json.str(r.get("root")), "container root, element type " + simple(et) + " has @" + simple(Type.getType(a.desc).getInternalName()));
            }
        }
    }

    private boolean isContainer(FieldInfo f) {
        if (f.desc.startsWith("[")) return true;
        Type t = Type.getType(f.desc);
        if (t.getSort() != Type.OBJECT) return false;
        String n = t.getInternalName();
        return an.isSubtype(n, "java/util/Collection") || an.isSubtype(n, "java/util/Map");
    }
}
