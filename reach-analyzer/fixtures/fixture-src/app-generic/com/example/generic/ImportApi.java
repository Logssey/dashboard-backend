package com.example.generic;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/** The same pattern on an interface with a default handler method. */
public interface ImportApi<D> {
    @PostMapping("/import")
    default String importOne(@RequestBody D body) {
        return "imported";
    }
}
