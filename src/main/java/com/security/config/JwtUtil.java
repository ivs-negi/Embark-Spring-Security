package com.security.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expirationMs}")
    private long expirationMs;

//    Getting demo key
    private SecretKey getKey(){
        return Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
    }

//    Getting token from header "Authorization"
    public String getTokenFromHeader(HttpServletRequest request){
        log.info("Getting token from header");
        String token = request.getHeader("Authorization");
        if(token != null && token.startsWith("Bearer ")){
            return token.substring(7);
        }
        return null;
    }

//   Generating token from username
    public String generateToken(UserDetails userDetails) {
        String username = userDetails.getUsername();
        log.info("Generating token for username {}", username);
        long currentTime = System.currentTimeMillis();
        return Jwts
                .builder()
                .subject(username)
                .issuedAt(new Date(currentTime))
                .expiration(new Date(currentTime + expirationMs))
                .signWith(getKey())
                .compact();
    }

//    Extracting username from token
    public String extractUsername(String token){
        log.info("Extracting username from token");
        return Jwts
                .parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

//    Validating a token
    public boolean validateToken(String token,String username){
        log.info("Validating token");
        try{
            String extractedUsername  = extractUsername(token);
            return  extractedUsername.equals(username) && !isTokenExpired(token);
        } catch (Exception e) {
            log.error("Invalid Token {}", e.getMessage());
            return false;
        }
    }

//    Checking if token is expired
    private boolean isTokenExpired(String token) {
        log.info("Checking if token is expired");
        return extractExpiration(token).before(new Date());
    }

//    Extracting token expiration date
    private Date extractExpiration(String token){
        log.info("extracting expiration time");
        return Jwts
                .parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }
}