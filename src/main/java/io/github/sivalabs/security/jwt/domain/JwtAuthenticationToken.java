package io.github.sivalabs.security.jwt.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@AllArgsConstructor
public class JwtAuthenticationToken {
    private String token;
    private Date expiresOn;
}
