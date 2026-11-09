package com.logssey.reach.analyzer;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Per-method summaries of the instructions the analysis cares about. Parsed lazily, once per class. */
final class Code {

    record Inv(int op, String owner, String name, String desc, int line) {}

    /** Target of an invokedynamic lambda / method reference (LambdaMetafactory). */
    record Lam(int tag, String owner, String name, String desc, int line) {}

    record At(String value, int line) {}

    static final class Summary {
        final List<Inv> invokes = new ArrayList<>();
        final List<At> news = new ArrayList<>();
        final Set<String> staticOwners = new LinkedHashSet<>();
        final List<Lam> lambdas = new ArrayList<>();
        final List<At> ldcStrings = new ArrayList<>();
        final List<At> typeRefs = new ArrayList<>(); // LDC class literals, CHECKCAST, INSTANCEOF, ANEWARRAY
        final List<At> classLiterals = new ArrayList<>(); // LDC Type only
    }

    private final ClassIndex idx;
    private final Map<String, Map<String, Summary>> cache = new HashMap<>();
    int parsedClasses;

    Code(ClassIndex idx) {
        this.idx = idx;
    }

    /** Summary of one method, or null if the class/method is unknown or has no body. */
    Summary of(String owner, String nameDesc) {
        Map<String, Summary> m = forClass(owner);
        return m == null ? null : m.get(nameDesc);
    }

    Map<String, Summary> forClass(String owner) {
        Map<String, Summary> m = cache.get(owner);
        if (m != null) return m;
        ClassInfo ci = idx.get(owner);
        if (ci == null || ci.bytes == null) return null;
        Map<String, Summary> out = new HashMap<>();
        try {
            new ClassReader(ci.bytes).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                    Summary s = new Summary();
                    out.put(name + desc, s);
                    return new Collector(s);
                }
            }, ClassReader.SKIP_FRAMES);
        } catch (RuntimeException e) {
            idx.warnings.add("cannot read code of " + owner + ": " + e);
        }
        parsedClasses++;
        cache.put(owner, out);
        return out;
    }

    private static final class Collector extends MethodVisitor {
        private final Summary s;
        private int line = -1;

        Collector(Summary s) {
            super(Opcodes.ASM9);
            this.s = s;
        }

        @Override
        public void visitLineNumber(int line, Label start) {
            this.line = line;
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            if (opcode == Opcodes.NEW) {
                s.news.add(new At(type, line));
            } else {
                String t = type.startsWith("[") ? elementInternalName(type) : type;
                if (t != null) s.typeRefs.add(new At(t, line));
            }
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {
            if (opcode == Opcodes.GETSTATIC || opcode == Opcodes.PUTSTATIC) s.staticOwners.add(owner);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.startsWith("[")) owner = "java/lang/Object"; // array clone() etc.
            s.invokes.add(new Inv(opcode, owner, name, desc, line));
            if (opcode == Opcodes.INVOKESTATIC) s.staticOwners.add(owner);
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... args) {
            if (!bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")) return;
            if (args.length > 1 && args[1] instanceof Handle h) {
                s.lambdas.add(new Lam(h.getTag(), h.getOwner(), h.getName(), h.getDesc(), line));
            }
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof String str) {
                s.ldcStrings.add(new At(str, line));
            } else if (value instanceof Type t && (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY)) {
                String n = t.getSort() == Type.ARRAY ? elementInternalName(t.getDescriptor()) : t.getInternalName();
                if (n != null) {
                    s.typeRefs.add(new At(n, line));
                    s.classLiterals.add(new At(n, line));
                }
            }
        }
    }

    static String elementInternalName(String arrayDesc) {
        Type t = Type.getType(arrayDesc);
        while (t.getSort() == Type.ARRAY) t = t.getElementType();
        return t.getSort() == Type.OBJECT ? t.getInternalName() : null;
    }
}
