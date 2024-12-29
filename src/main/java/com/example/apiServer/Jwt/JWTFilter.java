package com.example.apiServer.Jwt;

import com.example.apiServer.Entity.User;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String access = request.getHeader("access");

        if(access == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try{
            jwtUtil.isExpired(access);
        }catch(ExpiredJwtException e){
            //만료 시

            PrintWriter writer = response.getWriter();
            writer.println("access expired");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;

        }
        String category = jwtUtil.getCategory(access);

        if(!category.equals("access")){
            PrintWriter writer = response.getWriter();
            writer.println(" invalid access");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String username = jwtUtil.getUsername(access);
        String role = jwtUtil.getRole(access);

        User user = User.builder()
                .username(username)
                .role(role)
                .password("temp") //아무 값이나 상관 x
                .build();
        Authentication authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
