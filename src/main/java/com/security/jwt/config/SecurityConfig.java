package com.security.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.security.jwt.config.auth.PrincipalDetailsService;
import com.security.jwt.config.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final String[] AUTH_USER_LIST = {
            "/api/v1/user/**"
    };
    private static final String[] AUTH_MANAGER_LIST = {
            "/api/v1/manager/**"
    };
    private static final String[] AUTH_ADMIN_LIST = {
            "/api/v1/admin/**"
    };

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Autowired
    private CorsConfig corsConfig;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Autowired
    PrincipalDetailsService principalDetailsService;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthorityAuthorizationManager<RequestAuthorizationContext> userAuth = AuthorityAuthorizationManager
                .<RequestAuthorizationContext>hasRole("USER");
        AuthorityAuthorizationManager<RequestAuthorizationContext> managerAuth = AuthorityAuthorizationManager
                .<RequestAuthorizationContext>hasRole("MANAGER");
        AuthorityAuthorizationManager<RequestAuthorizationContext> adminAuth = AuthorityAuthorizationManager
                .<RequestAuthorizationContext>hasRole("ADMIN");

        userAuth.setRoleHierarchy(roleHierarchy());
        managerAuth.setRoleHierarchy(roleHierarchy());
        adminAuth.setRoleHierarchy(roleHierarchy());
        // SessionCreationPolicy.STATELESS : stateless. session을 만들지 않겠음
        // httpBasic().disable() :
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // .addFilterBefore(new MyFilter(), BasicAuthenticationFilter.class)
                // .addFilter(corsConfig.corsFilter())
                // .addFilter(new JwtAuthenticationFilter(authenticationProvider()))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(AUTH_USER_LIST).access(userAuth)
                        .requestMatchers(AUTH_MANAGER_LIST).access(managerAuth)
                        .requestMatchers(AUTH_ADMIN_LIST).access(adminAuth)
                        .anyRequest().permitAll());

        return http.build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        String role = "ROLE_ADMIN > ROLE_MANAGER > ROLE_USER";
        RoleHierarchyImpl r = new RoleHierarchyImpl();
        r.setHierarchy(role);
        return r;
    }
}