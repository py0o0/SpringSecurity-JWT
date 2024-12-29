package com.example.apiServer.Dto;

import com.example.apiServer.Entity.User;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UserDto {
    private String username;
    private String password;
    private String role;

    public User toEntity(UserDto userDto){
        return User.builder()
                .username(userDto.getUsername())
                .password(userDto.getPassword())
                .role(userDto.getRole())
                .build();
    }
}
