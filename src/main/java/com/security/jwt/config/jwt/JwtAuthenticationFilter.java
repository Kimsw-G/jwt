package com.security.jwt.config.jwt;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.jwt.config.auth.PrincipalDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

// /login으로 요청시, 
@RequiredArgsConstructor
@Component
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProperties jwtProperties;
    private final PrincipalDetailsService principalDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = "";
        try {
            token = jwtProperties.getToken(request);
        } catch (Exception e) {
            log.info("bad request : ",e);
        }
        log.info("dofilter is here");
        log.info("token : "+token);
        if(token !=null && jwtProperties.validateToken(token)){ // 토큰이 있으며, 유효한 토큰일때!
            String email = jwtProperties.extractUsername(token);

            UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
            if(userDetails != null){
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null, userDetails.getAuthorities());
                log.info("authentication user with email : {}",email);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        log.info("now it's time to filterchain.doFilter");
        filterChain.doFilter(request, response);
    }
    
}
