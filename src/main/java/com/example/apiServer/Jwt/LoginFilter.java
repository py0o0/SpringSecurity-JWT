package com.example.apiServer.Jwt;

import com.example.apiServer.Entity.RefreshToken;
import com.example.apiServer.Entity.User;
import com.example.apiServer.Repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter { //작성된 id와 password를 확인하는 필터
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        String username = obtainUsername(req);
        String password = obtainPassword(req);

        UsernamePasswordAuthenticationToken authToken //토큰으로 정보를 담아 authentication manager에게 전달
                = new UsernamePasswordAuthenticationToken(username, password, null);
        return authenticationManager.authenticate(authToken);
    }


    //로그인 성공 시 실행되는 메소드 (여기서 jwt발급하면 됨 )
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth){
        String username = auth.getName();

        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        Iterator<? extends GrantedAuthority> authoritiesIterator = authorities.iterator();
        GrantedAuthority authority = authoritiesIterator.next();
        String role = authority.getAuthority();                  //롤 확인

        String access = jwtUtil.createJwt("access", username, role, 6000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 3600000L);

        addRefresh(username, refresh, 3600000L);

        res.setHeader("access",access);
        res.addCookie(createCookie("refresh",refresh));
        res.setStatus(HttpServletResponse.SC_OK);

    }


    //로그인 실패 시 실행되는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                              AuthenticationException failed){
        res.setStatus(401);
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
