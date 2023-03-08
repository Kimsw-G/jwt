package com.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.model.User;
import com.security.jwt.repo.UserRepository;



@RestController
public class JwtController {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @GetMapping(value="/home")
    public String home() {
        String str = "<h1>home</h1><br>";
        str += """
                <form action='/login' method='post'>
                    <input type='text' name='username'>
                    <input type='password' name='password'>
                    <button type='submit'>gogo</button>
                </form>
                """;
        return str;
    }
    
    @PostMapping(value="join")
    public String join(@RequestBody User user) {
        // user.setPassword("password");
        // user.setUsername("id");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        
        userRepository.save(user);
        return "굿 회원가입";
    }
    
}