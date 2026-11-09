package com.logssey.reach.analyzer;

import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;

final class FieldInfo {
    final String name;
    final String desc;
    final String signature;
    final int access;
    final List<Ann> anns = new ArrayList<>();

    FieldInfo(int access, String name, String desc, String signature) {
        this.access = access;
        this.name = name;
        this.desc = desc;
        this.signature = signature;
    }

    boolean isStatic() {
        return (access & Opcodes.ACC_STATIC) != 0;
    }
}
