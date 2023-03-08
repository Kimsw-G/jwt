package com.security.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // json을 js에서 사용하도록 허용
        config.addAllowedOrigin("*"); // ip
        config.addAllowedHeader("*"); // header
        config.addAllowedMethod("*"); // method
        source.registerCorsConfiguration("/api/**", config); 

        return new CorsFilter(source);
    }
}
