package io.github.sivalabs.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.UUID;

@Setter
@Getter
@ConfigurationProperties(prefix="security.jwt")
public class JwtSecurityProperties {

    private String tokenHeader = "Authorization";

    private String tokenSchema = "Bearer ";

    private String secret = UUID.randomUUID().toString();

    private String issuer = "app";

    private long tokenValidityInSeconds = 1800;
}
