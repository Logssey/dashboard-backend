package com.logssey.reach.analyzer;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class MethodInfo {
    final String owner;
    final String name;
    final String desc;
    final String signature;
    final int access;
    final List<Ann> anns = new ArrayList<>();
    final Map<Integer, List<Ann>> paramAnns = new HashMap<>();
    int annotableParams = -1; // from visitAnnotableParameterCount (visible), -1 if not reported

    MethodInfo(String owner, int access, String name, String desc, String signature) {
        this.owner = owner;
        this.access = access;
        this.name = name;
        this.desc = desc;
        this.signature = signature;
    }

    MRef ref() {
        return new MRef(owner, name, desc);
    }

    boolean isAbstract() {
        return (access & Opcodes.ACC_ABSTRACT) != 0;
    }

    boolean isNative() {
        return (access & Opcodes.ACC_NATIVE) != 0;
    }

    boolean isStatic() {
        return (access & Opcodes.ACC_STATIC) != 0;
    }

    boolean isPrivate() {
        return (access & Opcodes.ACC_PRIVATE) != 0;
    }

    boolean hasBody() {
        return !isAbstract() && !isNative();
    }

    /** Annotations of the i-th declared parameter (corrects javac's synthetic-parameter offset). */
    List<Ann> annsOfParam(int i) {
        int argc = Type.getArgumentTypes(desc).length;
        int offset = (annotableParams > 0 && annotableParams < argc) ? argc - annotableParams : 0;
        List<Ann> l = paramAnns.get(i - offset);
        return l == null ? List.of() : l;
    }
}
