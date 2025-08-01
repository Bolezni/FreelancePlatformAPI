package org.example.authmodel.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Getter
public class JwtService {

    @Value("${application.security.jwt.secret-ket}")
    private String secret;

    @Value("${application.security.jwt.expiration}")
    private Long tokenExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private Long refreshTokenExpiration;

    @Value("${application.security.jwt.token-name}")
    private String tokenName;

    @Value("${application.security.jwt.refreshToken-name}")
    private String refreshToken;

    public String createJwtTokenRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, refreshTokenExpiration);
    }

    public String createJwtToken(UserDetails userDetails) {
        return buildToken(userDetails, tokenExpiration);
    }

    private String buildToken(UserDetails userDetails, long tokenExpiration) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .signWith(getSecretKey())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return getClaims(token, Claims::getSubject);
    }

    private Date getExpirationDate(String token) {
        Date date = getClaims(token, Claims::getExpiration);
        return date;
    }

    private boolean isTokenExpired(String token) {
        Date date = getExpirationDate(token);
        return !date.before(new Date());
    }

    public boolean isTokenValidate(String token, UserDetails userDetails) {
        boolean isValid = isTokenExpired(token);
        String username = getUserNameFromJwtToken(token);
        return (username.equals(userDetails.getUsername()) && isValid);
    }

    private <T> T getClaims(String token, Function<Claims, T> claimsResolver) {
        Claims claims = getAllClaim(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaim(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            throw new JwtException("Invalid JWT token: " + e.getMessage());
        }
    }

    private SecretKey getSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
