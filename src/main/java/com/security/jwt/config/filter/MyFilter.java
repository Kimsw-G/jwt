package com.security.jwt.config.filter;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class MyFilter implements Filter{

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        req.setCharacterEncoding("UTF-8");

        // ID, PW 가 정상적으로 들어와 로그인시, 토큰을 생성해줌
        // 요청시마다 header에 Authorization토큰을 가져옴
        // 토큰을 검증함
        if(req.getMethod().equals("POST")){ 
            System.out.println("post 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            // if(headerAuth.equals("cos")){
            //     chain.doFilter(req,res);
            // }else{
            //     PrintWriter out = res.getWriter();
            //     out.println("인증안됨");
            // }
        }


        chain.doFilter(request, response);
    }
    
}
