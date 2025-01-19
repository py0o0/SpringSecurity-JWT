package com.example.jwtpratice.controller;

import com.example.jwtpratice.service.UserService;
import io.jsonwebtoken.security.Request;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/join")
    public ResponseEntity<?> join(String id, String password) {
         if(!userService.join(id,password))
             return ResponseEntity.badRequest().body("회원가입 실패");
         return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/plz")
    public String plz(){
        return "plz";
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        return userService.reissue(request,response);
    }
}
