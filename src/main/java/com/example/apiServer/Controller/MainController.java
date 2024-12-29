package com.example.apiServer.Controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String mainP(){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        return "mian " + name;
    }

    @GetMapping("/do")
    public String doP(){
        return "mddddd";
    }
}
