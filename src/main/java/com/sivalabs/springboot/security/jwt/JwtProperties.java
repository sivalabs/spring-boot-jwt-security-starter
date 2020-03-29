package com.sivalabs.springboot.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Positive;
import java.util.List;

import static java.util.Arrays.asList;

@ConfigurationProperties(prefix = "security.jwt")
@Setter @Getter
@Validated
public class JwtProperties {

    // --------------- Defaults -------------------- //
    private static final Long DEFAULT_JWT_TOKEN_EXPIRES = 604800L;
    private static final String DEFAULT_BASE_PATH = "/api/**";
    private static final String DEFAULT_CREATE_AUTH_TOKEN_PATH = "/api/auth/login";
    private static final String DEFAULT_REFRESH_AUTH_TOKEN_PATH = "/api/auth/refresh";
    private static final String DEFAULT_AUTH_ME_PATH = "/api/auth/me";

    // ---------------------------------------------- //

    @NotEmpty(message = "issuer can not be empty")
    private String issuer = "";

    @NotEmpty(message = "header can not be empty")
    private String header = "Authorization";

    @NotEmpty(message = "expiresIn can not be empty")
    @Positive(message = "Expiry time can not be less than 1")
    private Long expiresIn = DEFAULT_JWT_TOKEN_EXPIRES;

    @NotEmpty(message = "secret can not be empty")
    private String secret = "";

    @NotEmpty(message = "basePath can not be empty")
    private String basePath = DEFAULT_BASE_PATH;
    private List<String> permitAllPaths = asList(
            DEFAULT_CREATE_AUTH_TOKEN_PATH,
            DEFAULT_REFRESH_AUTH_TOKEN_PATH
    );
    private boolean authApiEnabled = true;
    private String createAuthTokenPath = DEFAULT_CREATE_AUTH_TOKEN_PATH;
    private String refreshAuthTokenPath = DEFAULT_REFRESH_AUTH_TOKEN_PATH;
    private String authMePath = DEFAULT_AUTH_ME_PATH;
}
