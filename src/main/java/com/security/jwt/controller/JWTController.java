package com.security.jwt.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class JWTController {
    @GetMapping(value="home")
    public String getMethodName() {
        return "<h1>home</h1>";
    }
    
    
}