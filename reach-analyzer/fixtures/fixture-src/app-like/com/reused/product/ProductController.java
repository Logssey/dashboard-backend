package com.reused.product;

import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductController {
    @GetMapping("/products")
    public List<ProductResponse> list() {
        return List.of(new ProductResponse(1L, "chair", new BigDecimal("12000")));
    }
}
