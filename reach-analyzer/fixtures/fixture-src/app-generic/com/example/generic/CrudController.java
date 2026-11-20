package com.example.generic;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/** A shared CRUD controller: the request body is a type variable, each subclass names the real type. */
public abstract class CrudController<T> {
    @PostMapping
    public String create(@RequestBody T body) {
        return "created";
    }

    /** A type variable of the method itself: nothing names a type, Spring reads the body as Object. */
    @PostMapping("/echo")
    public <X> String echo(@RequestBody X body) {
        return "echo";
    }
}
