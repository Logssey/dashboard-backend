package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

import org.springframework.stereotype.Controller;
@Controller
@ResponseBody
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RestController {
    String value() default "";
}
