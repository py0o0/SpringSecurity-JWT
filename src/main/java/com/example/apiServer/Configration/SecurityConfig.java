package com.example.apiServer.Configration;

import com.example.apiServer.Jwt.CustomLogoutFilter;
import com.example.apiServer.Jwt.JWTFilter;
import com.example.apiServer.Jwt.JWTUtil;
import com.example.apiServer.Jwt.LoginFilter;
import com.example.apiServer.Repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
    throws Exception
    {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        

        http.csrf(csrf -> csrf.disable());

        http. formLogin(auth -> auth.disable());

        http.httpBasic(auth -> auth.disable()); //다른 로그인 방시 disalbe

        http.authorizeHttpRequests(auth->auth
                .requestMatchers("/login","/join","/","/reissue").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

        //login 필터앞에 jwt 필터 삽입
        http.addFilterBefore(new JWTFilter(jwtUtil), LogoutFilter.class);

        //UsernamePasswordAuthenticationFilter 자리에 LoginFilter로 커스텀 필터 대체
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration),jwtUtil,refreshRepository),
                UsernamePasswordAuthenticationFilter.class);

        http.addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);

        http.sessionManagement(session -> session //세션 stateless
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
