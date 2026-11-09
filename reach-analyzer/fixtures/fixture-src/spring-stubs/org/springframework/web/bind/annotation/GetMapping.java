package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

@RequestMapping
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface GetMapping {
    String[] value() default {};
}
