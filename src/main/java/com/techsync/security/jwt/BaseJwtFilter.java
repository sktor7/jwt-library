package com.techsync.security.jwt;

import io.jsonwebtoken.Claims; 

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public abstract class BaseJwtFilter extends OncePerRequestFilter {
	
    protected final JwtUtil jwtUtil;


    public BaseJwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    protected List<String> getDefaultExcludedUrls() {
        return Arrays.asList(
            "/swagger-ui",
            "/swagger-resources",
            "/v2/api-docs",
            "/v3/api-docs",
            "/webjars"
        );
    }
    
    protected List<String> getAdditionalExcludedUrls() {
        return Collections.emptyList();
    }
    
    protected List<String> getRemovedExcludedUrls() {
        return Collections.emptyList();
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        List<String> allExcludedUrls = new ArrayList<>();
        allExcludedUrls.addAll(getDefaultExcludedUrls());
        allExcludedUrls.addAll(getAdditionalExcludedUrls());

        allExcludedUrls.removeAll(getRemovedExcludedUrls());

        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) ||
        		"/".equals(requestURI) ||
        	    allExcludedUrls.stream().anyMatch(requestURI::startsWith)) {
        	    chain.doFilter(request, response);
        	    return;
        	}
        
        String header = request.getHeader("Authorization");
        System.out.println("Authorization Header: " + header);

        if (header == null || !header.startsWith("Bearer ")) {
            System.out.println("No Bearer token found");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: Missing or invalid JWT token");
            return;
        }

        String token = header.substring(7); 
        System.out.println("JWT Token: " + token);

        try {
            Claims claims = jwtUtil.validateToken(token);
            System.out.println("JWT Token validated: " + claims.getSubject());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                claims.getSubject(),  
                null,
                new ArrayList<>() 
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception e) {
            System.out.println("JWT validation failed: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        chain.doFilter(request, response); 
    }
}
