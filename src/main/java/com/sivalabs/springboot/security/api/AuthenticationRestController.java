package com.sivalabs.springboot.security.api;

import com.sivalabs.springboot.security.jwt.JwtProperties;
import com.sivalabs.springboot.security.jwt.domain.AuthenticatedUser;
import com.sivalabs.springboot.security.jwt.domain.AuthenticationRequest;
import com.sivalabs.springboot.security.jwt.domain.AuthenticationToken;
import com.sivalabs.springboot.security.jwt.token.TokenHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class AuthenticationRestController {
    private final AuthenticationManager authenticationManager;
    private final TokenHelper tokenHelper;
    private final JwtProperties securityConfigProperties;

    @PostMapping(value = "${security.jwt.create-auth-token-path:/api/auth/login}")
    public AuthenticationToken createAuthenticationToken(@RequestBody AuthenticationRequest credentials) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();
        String jws = tokenHelper.generateToken(user.getUsername());
        return new AuthenticationToken(jws, securityConfigProperties.getExpiresIn());
    }

    @PostMapping(value = "${security.jwt.refresh-auth-token-path:/api/auth/refresh}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<AuthenticationToken> refreshAuthenticationToken(HttpServletRequest request) {
        String authToken = tokenHelper.getToken(request);
        String refreshedToken = tokenHelper.refreshToken(authToken);
        return ResponseEntity.ok(
                new AuthenticationToken(
                        refreshedToken,
                        securityConfigProperties.getExpiresIn()
                )
        );
    }

    @PostMapping(value = "${security.jwt.auth-me-path:/api/auth/me}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<AuthenticatedUser> me() {
        User loginUser = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Set<String> roles = loginUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(loginUser.getUsername(), roles);
        return ResponseEntity.ok(authenticatedUser);
    }
}
