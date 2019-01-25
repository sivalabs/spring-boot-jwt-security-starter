package com.sivalabs.security.jwt.demo;

import io.github.sivalabs.security.jwt.EnableJwtSecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication
public class SpringBootJwtSecurityStarterDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootJwtSecurityStarterDemoApplication.class, args);
    }

}

@Configuration
@EnableJwtSecurity
class TestJwtWebSecurity {

}
