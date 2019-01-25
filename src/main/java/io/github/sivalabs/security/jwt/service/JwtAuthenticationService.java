package io.github.sivalabs.security.jwt.service;

import io.github.sivalabs.security.jwt.domain.JwtAuthenticationToken;
import io.github.sivalabs.security.jwt.domain.UserCredentials;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class JwtAuthenticationService {

    private final AuthenticationManager authenticationManager;

    private final UserDetailsService userDetailsService;

    private final JwtTokenService tokenService;

    public JwtAuthenticationService(AuthenticationManager authenticationManager,
                                    UserDetailsService userDetailsService,
                                    JwtTokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.tokenService = tokenService;
    }

    public JwtAuthenticationToken authenticate(UserCredentials userCredentials) {
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userCredentials.getUsername(),
                        userCredentials.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = userDetailsService.loadUserByUsername((String) authentication.getPrincipal());
        return tokenService.generateToken(userDetails);
    }
}
