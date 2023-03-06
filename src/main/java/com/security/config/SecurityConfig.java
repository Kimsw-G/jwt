package com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class SecurityConfig {
    private static final String[] AUTH_LIST = {
        "/api/v1/user/**"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthorityAuthorizationManager<RequestAuthorizationContext> auth
            = AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("ADMIN");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .formLogin().disable()
        .httpBasic().disable()
        .authorizeHttpRequests(authorize->authorize
            .requestMatchers(AUTH_LIST).access(auth)
        );

        return http.build();
    }
}