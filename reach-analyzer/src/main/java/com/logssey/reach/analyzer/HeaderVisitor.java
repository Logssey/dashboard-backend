package com.logssey.reach.analyzer;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;

/** Reads class headers: hierarchy, members, annotations (no method bodies). */
final class HeaderVisitor extends ClassVisitor {
    private final ClassInfo ci;

    HeaderVisitor(ClassInfo ci) {
        super(Opcodes.ASM9);
        this.ci = ci;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        ci.access = access;
        ci.superName = superName;
        ci.interfaces = interfaces == null ? new String[0] : interfaces;
        ci.signature = signature;
    }

    @Override
    public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
        Ann a = new Ann(desc);
        ci.anns.add(a);
        return new AnnCollector(a.values);
    }

    @Override
    public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
        FieldInfo f = new FieldInfo(access, name, desc, signature);
        ci.fields.add(f);
        return new FieldVisitor(Opcodes.ASM9) {
            @Override
            public AnnotationVisitor visitAnnotation(String d, boolean visible) {
                Ann a = new Ann(d);
                f.anns.add(a);
                return new AnnCollector(a.values);
            }
        };
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodInfo m = new MethodInfo(ci.name, access, name, desc, signature);
        ci.methods.put(name + desc, m);
        return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public AnnotationVisitor visitAnnotation(String d, boolean visible) {
                Ann a = new Ann(d);
                m.anns.add(a);
                return new AnnCollector(a.values);
            }

            @Override
            public void visitAnnotableParameterCount(int parameterCount, boolean visible) {
                if (visible) m.annotableParams = parameterCount;
            }

            @Override
            public AnnotationVisitor visitParameterAnnotation(int parameter, String d, boolean visible) {
                Ann a = new Ann(d);
                m.paramAnns.computeIfAbsent(parameter, k -> new ArrayList<>()).add(a);
                return new AnnCollector(a.values);
            }
        };
    }
}
