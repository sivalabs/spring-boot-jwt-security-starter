package io.github.sivalabs.security.jwt.service;

import io.github.sivalabs.security.jwt.JwtSecurityProperties;
import io.github.sivalabs.security.jwt.domain.JwtAuthenticationToken;
import io.github.sivalabs.security.jwt.domain.UserCredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenService {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    private final JwtSecurityProperties jwtSecurityProperties;

    @Autowired
    public JwtTokenService(JwtSecurityProperties jwtSecurityProperties) {
        this.jwtSecurityProperties = jwtSecurityProperties;
    }

    JwtAuthenticationToken generateToken(UserDetails userDetails) {
        Date expirationDate = generateExpirationDate();
        String token = Jwts.builder()
                .setIssuer(jwtSecurityProperties.getIssuer())
                .setSubject(userDetails.getUsername())
                .setAudience("WEB")
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .claim("roles",
                        userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()))
                .signWith(SIGNATURE_ALGORITHM, jwtSecurityProperties.getSecret())
                .compact();

        return new JwtAuthenticationToken(token, expirationDate);
    }

    public String getAuthToken(HttpServletRequest request) {
        String authHeader = getAuthHeaderFromHeader(request);
        String tokenSchema = jwtSecurityProperties.getTokenSchema();
        if (authHeader != null && authHeader.startsWith(tokenSchema)) {
            return authHeader.substring(tokenSchema.length());
        }
        return null;
    }

    public UserCredentials getUserCredentialsFromToken(String token) {
        Claims claims = parseAuthToken(token);
        UserCredentials userCredentials = new UserCredentials();
        userCredentials.setUsername(claims.getSubject());
        userCredentials.setPassword("");
        return userCredentials;
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        return getUserCredentialsFromToken(token).getUsername()
                .equals(userDetails.getUsername());
    }

    private Claims parseAuthToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecurityProperties.getSecret())
                .parseClaimsJws(token)
                .getBody();
    }

    private Date generateExpirationDate() {
        return new Date(new Date().getTime() + jwtSecurityProperties.getTokenValidityInSeconds() * 1000);
    }

    private String getAuthHeaderFromHeader(HttpServletRequest request) {
        return request.getHeader(jwtSecurityProperties.getTokenHeader());
    }

}
