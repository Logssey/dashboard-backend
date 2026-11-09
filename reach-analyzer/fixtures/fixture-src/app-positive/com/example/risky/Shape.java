package com.example.risky;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", defaultImpl = Circle.class)
@JsonSubTypes({@JsonSubTypes.Type(value = Circle.class, name = "circle")})
public abstract class Shape {
}
