package com.example.jwtpratice.service;

import com.example.jwtpratice.entity.User;
import com.example.jwtpratice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(!userRepository.existsByEmail(username))
            throw new UsernameNotFoundException("User not found");
        return userRepository.findByEmail(username);
    }
}
