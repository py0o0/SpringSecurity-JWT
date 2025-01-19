package com.example.jwtpratice.config;

import com.example.jwtpratice.jwt.JwtFilter;
import com.example.jwtpratice.jwt.JwtLoginFilter;
import com.example.jwtpratice.jwt.JwtUtil;
import com.example.jwtpratice.repository.RefreshRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf->csrf.disable());

        http.formLogin(form->form.disable());

        http.httpBasic(httpBasic->httpBasic.disable());

        http.authorizeHttpRequests(auth->auth
                .requestMatchers("/login", "/join","/reissue").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());

        http.sessionManagement(session -> session //세션 무효화
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.addFilterBefore(new JwtFilter(jwtUtil), LogoutFilter.class);

        http.addFilterAt(new JwtLoginFilter(authenticationManager(authenticationConfiguration),jwtUtil,refreshRepository),
                UsernamePasswordAuthenticationFilter.class);

        http.logout(logout -> logout
                .logoutUrl("/logout")
                .addLogoutHandler(logoutHandler())  // 로그아웃 시 실행할 핸들러 추가
                .logoutSuccessHandler(logoutSuccessHandler())  // 로그아웃 성공 핸들러 추가
        );
        
        return http.build();
    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
        };
    }

    private LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            String refresh = null;
            Cookie[] cookies = request.getCookies();
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refresh")) {
                    refresh = cookie.getValue();
                }
            }
            if (refresh == null)
                throw new IllegalArgumentException("Refresh token is missing");


            Cookie cookie = new Cookie("refresh",refresh);
            cookie.setMaxAge(0);
            cookie.setPath("/");
            response.addCookie(cookie);

            String email = jwtUtil.getEmail(refresh);
            refreshRepository.deleteByEmail(email);
        };
    }


}
