package io.github.sivalabs.security.jwt.domain;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserCredentials {
    private String username;
    private String password;
}
