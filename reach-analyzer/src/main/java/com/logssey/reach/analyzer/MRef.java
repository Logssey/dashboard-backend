package com.logssey.reach.analyzer;

/** Reference to a method: owner (internal name) + name + descriptor. */
record MRef(String owner, String name, String desc) {
    String key() {
        return owner + "." + name + desc;
    }

    String pretty() {
        return owner.replace('/', '.') + "." + name + desc;
    }

    String shortName() {
        String o = owner.substring(owner.lastIndexOf('/') + 1);
        return o + "." + name;
    }
}
