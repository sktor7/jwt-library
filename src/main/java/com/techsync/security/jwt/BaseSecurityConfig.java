package com.techsync.security.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.Customizer;

public abstract class BaseSecurityConfig extends WebSecurityConfigurerAdapter {

	protected final BaseJwtFilter jwtFilter;

	@Autowired
    public BaseSecurityConfig(BaseJwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        	.cors(Customizer.withDefaults())
            .csrf().disable()
            .authorizeRequests()
            .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .antMatchers(getFinalExcludedUrls().toArray(new String[0])).permitAll()
            .anyRequest().authenticated()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
	
	protected List<String> getDefaultExcludedUrls() {
        return Arrays.asList("/swagger-ui.html", "/swagger-resources/**", "/v2/api-docs", "/webjars/**");
    }

	protected List<String> getAdditionalExcludedUrls() {
        return Collections.emptyList();
    }
    
    protected List<String> getRemovedExcludedUrls() {
        return Collections.emptyList();
    }
    
    private List<String> getFinalExcludedUrls() {
        List<String> finalUrls = new ArrayList<>(getDefaultExcludedUrls());
        finalUrls.addAll(getAdditionalExcludedUrls());
        finalUrls.removeAll(getRemovedExcludedUrls());
        return finalUrls;
    }
}
