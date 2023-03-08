package com.security.jwt.config.jwt;

import java.io.BufferedReader;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.User;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

// /login으로 요청시, 
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // private final AuthenticationManager authenticationManager;
    private final AuthenticationProvider authenticationProvider;

    // /login 요청시 로그인 시도를 위해 실행 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("jwt 시도중!");

        // username, password를 받기
        // login check
        // authentication 로긍 시도?
        // => PrincipalDetails가 호출, loadUserByUsername() 이 실행된다
        Authentication authentication = null;
        try {
            // BufferedReader br = request.getReader();
            // String input = null;
            // while ((input=br.readLine())!=null) {
            // System.out.println(input);
            // }
            // System.out.println(request.getInputStream().toString());
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user.getUsername(), user.getPassword());
            // 로그인 한 정보가 담김
            authentication = authenticationProvider.authenticate(authenticationToken);
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            System.out.println(principalDetails.getUser().getUsername());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // PrincipalDetails를 Session에 담음
        // jwt 토큰을 통해 응답!
        // Session에 담지 않으면 권한 관리가 안 됨 ㅜ

        return authentication;
    }

}
