package com.sivalabs.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

    @GetMapping("/api/health")
    public String apiHealth() {
        return "UP";
    }

    @GetMapping("/public/status")
    public String publicStatus() {
        return "HelloWorld";
    }

    @GetMapping("/api/data")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String getData() {
        return "Here is the data";
    }
}
