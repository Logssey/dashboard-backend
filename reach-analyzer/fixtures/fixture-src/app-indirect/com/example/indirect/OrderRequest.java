package com.example.indirect;

import java.math.BigDecimal;
import java.util.List;

/** BigDecimal two levels down, behind a generic List. */
public record OrderRequest(String memo, List<OrderRequest.Line> lines) {
    public record Line(String sku, BigDecimal unitPrice) {
    }
}
