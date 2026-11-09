package com.logssey.reach.analyzer;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Records annotation element values in plain Java objects (String, Number, List, Map). */
final class AnnCollector extends AnnotationVisitor {
    private final Map<String, Object> target;
    private final List<Object> list;

    AnnCollector(Map<String, Object> target) {
        super(Opcodes.ASM9);
        this.target = target;
        this.list = null;
    }

    AnnCollector(List<Object> list) {
        super(Opcodes.ASM9);
        this.target = null;
        this.list = list;
    }

    private void put(String n, Object v) {
        if (list != null) list.add(v);
        else target.put(n, v);
    }

    @Override
    public void visit(String n, Object v) {
        if (v instanceof Type t) {
            put(n, t.getDescriptor());
        } else if (v != null && v.getClass().isArray()) {
            List<Object> l = new ArrayList<>();
            for (int k = 0; k < Array.getLength(v); k++) l.add(Array.get(v, k));
            put(n, l);
        } else {
            put(n, v);
        }
    }

    @Override
    public void visitEnum(String n, String desc, String value) {
        put(n, desc + "#" + value);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String n, String desc) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("@type", desc);
        put(n, m);
        return new AnnCollector(m);
    }

    @Override
    public AnnotationVisitor visitArray(String n) {
        List<Object> l = new ArrayList<>();
        put(n, l);
        return new AnnCollector(l);
    }
}
