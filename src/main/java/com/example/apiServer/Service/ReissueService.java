package com.example.apiServer.Service;

import com.example.apiServer.Entity.RefreshToken;
import com.example.apiServer.Jwt.JWTUtil;
import com.example.apiServer.Repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class ReissueService {
    private final JWTUtil jwtUtil;
    private final RefreshRepository repository;
    private final RefreshRepository refreshRepository;


    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }
        if(refresh == null) { //해당 쿠키가 있는지
            return new ResponseEntity<>("refresh null", HttpStatus.BAD_REQUEST);
        }

        try{
            jwtUtil.isExpired(refresh);
        }catch(ExpiredJwtException e){ //만기 됫는지
            refreshRepository.deleteByRefresh(refresh);
            return new ResponseEntity<>("refresh expired", HttpStatus.BAD_REQUEST);
        }

        String category = jwtUtil.getCategory(refresh);
        if(!category.equals("refresh")) { //리프레시인지
            return new ResponseEntity<>("invalid refresh", HttpStatus.BAD_REQUEST);
        }

        if(!refreshRepository.existsByRefresh(refresh)){
            return new ResponseEntity<>("invalid refresh", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccess = jwtUtil.createJwt("access",username,role,60000L);
        String newRefresh = jwtUtil.createJwt("refresh",username,role,3600000L);

        refreshRepository.deleteByRefresh(refresh); //기존 삭제
        addRefresh(username,newRefresh,3600000L); //새로 저장

        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh",newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }
    private void addRefresh(String username, String refresh, long exp) {
        RefreshToken refreshToken = RefreshToken.builder()
                .username(username)
                .refresh(refresh)
                .expiration(new Date(System.currentTimeMillis() + exp).toString())
                .build();
        refreshRepository.save(refreshToken);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);
        return cookie;
    }
}
