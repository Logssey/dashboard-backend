package com.example.indirect;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

/** @JsonTypeInfo(defaultImpl) on the field, not on the type. */
public record PetRequest(@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, defaultImpl = PetRequest.Dog.class) Animal pet) {
    public interface Animal {
    }

    public record Dog(String name) implements Animal {
    }
}
