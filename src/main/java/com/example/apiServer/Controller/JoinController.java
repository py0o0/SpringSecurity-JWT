package com.example.apiServer.Controller;

import com.example.apiServer.Dto.UserDto;
import com.example.apiServer.Service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(UserDto userDto){
        joinService.joinPrc(userDto);
        return "ok";
    }
}
