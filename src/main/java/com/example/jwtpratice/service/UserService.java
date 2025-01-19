package com.example.jwtpratice.service;

import com.example.jwtpratice.entity.Refresh;
import com.example.jwtpratice.entity.User;
import com.example.jwtpratice.jwt.JwtUtil;
import com.example.jwtpratice.repository.RefreshRepository;
import com.example.jwtpratice.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public boolean join(String id, String password) {
        if(userRepository.existsByEmail(id))
            return false;
        User user = new User();
        user.setEmail(id);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return true;
    }

    public ResponseEntity<?> reissue(HttpServletRequest req, HttpServletResponse res) {
        String refresh = null;
        Cookie[] cookies = req.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }
        if (refresh == null)
            return new ResponseEntity<>("refresh null", HttpStatus.BAD_REQUEST);

        try{
            jwtUtil.isExpired(refresh);
        }catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh expired", HttpStatus.BAD_REQUEST);
        }

        String category = jwtUtil.getCategory(refresh);
        if(!category.equals("refresh"))
            return new ResponseEntity<>("invalid refresh", HttpStatus.BAD_REQUEST);

        if(!refreshRepository.existsByRefresh(refresh))
            return new ResponseEntity<>("invalid refresh", HttpStatus.BAD_REQUEST);

        String email = jwtUtil.getEmail(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccess = jwtUtil.createJwt("access",email,role,10L * 60L * 1000L);
        String newRefresh = jwtUtil.createJwt("refresh",email,role,30L * 60L * 1000L);

        refreshRepository.deleteByEmail(email);
        addRefresh(email,refresh,30L * 60L * 1000L);

        res.setHeader("access",newAccess);
        res.addCookie(createCookie("refresh",newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);

    }
    private void addRefresh(String email, String refresh, long exp) {
        Refresh refreshToken = new Refresh();
        refreshToken.setEmail(email);
        refreshToken.setRefresh(refresh);
        refreshToken.setExpiration(new Date(System.currentTimeMillis() + exp).toString());
        refreshRepository.save(refreshToken);
    }


    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);
        return cookie;
    }

}
