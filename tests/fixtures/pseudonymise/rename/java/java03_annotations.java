package com.bank.api;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import org.springframework.web.bind.annotation.GetMapping;

@Entity
@Table(name = "mandate_registry")
public class Mandate {
    @Column(name = "nach_reference", length = 40)
    private String nachReference;

    @GetMapping(value = "/mandates", produces = "application/json")
    public String list() {
        return nachReference;
    }
}

@interface Audited {
    String reason() default "festival";
}
