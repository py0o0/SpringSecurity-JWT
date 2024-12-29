package com.example.apiServer.Service;

import com.example.apiServer.Dto.UserDto;
import com.example.apiServer.Entity.User;
import com.example.apiServer.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinPrc(UserDto userDto){

        if(userRepository.existsByUsername(userDto.getUsername())){
            return;
        }
        User user = User.builder()
                .username(userDto.getUsername())
                .password(bCryptPasswordEncoder.encode(userDto.getPassword()))
                .role("ROLE_USER")
                .build();
        userRepository.save(user);
    }
}
