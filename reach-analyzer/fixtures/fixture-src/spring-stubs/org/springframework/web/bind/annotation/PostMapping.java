package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

@RequestMapping
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PostMapping {
    String[] value() default {};
}
