package com.logssey.reach.analyzer;

import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ClassInfo {
    final String name;
    final String origin; // "app", the library jar file name, or "jdk"
    final boolean app;
    final byte[] bytes; // raw class file, null for JDK header-only entries
    String superName;
    String[] interfaces = new String[0];
    int access;
    String signature;
    final Map<String, MethodInfo> methods = new LinkedHashMap<>(); // key: name + desc
    final List<FieldInfo> fields = new ArrayList<>();
    final List<Ann> anns = new ArrayList<>();

    ClassInfo(String name, String origin, boolean app, byte[] bytes) {
        this.name = name;
        this.origin = origin;
        this.app = app;
        this.bytes = bytes;
    }

    boolean isInterface() {
        return (access & Opcodes.ACC_INTERFACE) != 0;
    }

    boolean isAbstract() {
        return (access & Opcodes.ACC_ABSTRACT) != 0;
    }

    boolean isConcrete() {
        return !isInterface() && !isAbstract();
    }
}
