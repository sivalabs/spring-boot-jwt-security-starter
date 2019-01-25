package io.github.sivalabs.security.jwt.web;

import io.github.sivalabs.security.jwt.domain.JwtAuthenticationToken;
import io.github.sivalabs.security.jwt.domain.UserCredentials;
import io.github.sivalabs.security.jwt.service.JwtAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/auth")
@ConditionalOnProperty(prefix = "security.jwt", name = "authentication", matchIfMissing = true)
public class JwtAuthenticationController {

    private final JwtAuthenticationService authenticationService;

    @Autowired
    public JwtAuthenticationController(JwtAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/authenticate")
    public JwtAuthenticationToken authenticate(
            @RequestBody UserCredentials userCredentials) {
        return authenticationService.authenticate(userCredentials);
    }
}
