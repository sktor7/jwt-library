package com.techsync.security.jwt;

import io.jsonwebtoken.*; 
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {
	
	@Value("${jwt.secret}")
    private String secretKey;
	
    private Key key;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes()); 
    }
     
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 7; 

    	public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);

        return Jwts.builder()
        	    .setSubject(username) 
        	    .setIssuedAt(new Date())
        	    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        	    .signWith(key, SignatureAlgorithm.HS256)
        	    .compact();
    }
    
    public Claims validateToken(String token) throws JwtException {
        try {

        	Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        	
        	System.out.println("Claims: " + claims);
        	
        	Date expiration = claims.getExpiration();
        	System.out.println("Token Expiration: " + expiration);
        	
            return claims;
        } catch (Exception e) {
            System.out.println("Token validation failed: " + e.getMessage());
            throw new JwtException("Invalid token");
        }
    }
}
