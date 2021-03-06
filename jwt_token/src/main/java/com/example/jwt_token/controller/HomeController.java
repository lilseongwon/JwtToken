package com.example.jwt_token.controller;

import com.example.jwt_token.security.JwtProvider;
import com.example.jwt_token.service.CustomUserDetailsService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class HomeController {

    private final CustomUserDetailsService userDetailsService;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager; // authenticate 메서드 : username, password 기반 인증 수행

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @PostMapping("/auth")
    public ResponseEntity<LoginSuccessResponse> authenticateTest(@RequestBody LoginRequest loginRequest) {
        log.info("/auth 호출");
        try {
            // username, password 인증 시도
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("로그인 실패");
        }
        // 인증 성공 후 인증된 user의 정보를 갖고옴
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.username);
        // subject, claim 모두 UserDetails를 사용하므로 객체를 그대로 전달
        String token = jwtProvider.generateToken(userDetails);

        // 생성된 토큰을 응답 (Test)
        return ResponseEntity.ok(new LoginSuccessResponse(token));
    }
    // 인증요청 객체
    @AllArgsConstructor
    @Data
    static class LoginRequest{
        private String username;
        private String password;
    }
    // 인증요청에 대한 응답 객체
    @AllArgsConstructor
    @Data
    static class LoginSuccessResponse {
        private String token;
    }
}