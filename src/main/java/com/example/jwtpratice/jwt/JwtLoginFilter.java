package com.example.jwtpratice.jwt;

import com.example.jwtpratice.entity.Refresh;
import com.example.jwtpratice.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res)
            throws AuthenticationException {
        String email = obtainUsername(req);
        String password = obtainPassword(req);

        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(email, password, null);
        return authenticationManager.authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                        HttpServletResponse res,
                                        FilterChain chain,
                                        Authentication auth) {
        String email = auth.getName();
        String role = auth.getAuthorities().iterator().next().getAuthority();

        String access = jwtUtil.createJwt("access",email,role,10L * 60L * 1000L);
        String refresh = jwtUtil.createJwt("refresh",email,role,30L * 60L * 1000L);

        refreshRepository.deleteByEmail(email);
        addRefresh(email,refresh,30L * 60L * 1000L);

        res.setHeader("access",access);
        res.addCookie(createCookie("refresh",refresh));
        res.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                              AuthenticationException failed){
        System.out.println("왜 실패?");
        res.setStatus(401);
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
