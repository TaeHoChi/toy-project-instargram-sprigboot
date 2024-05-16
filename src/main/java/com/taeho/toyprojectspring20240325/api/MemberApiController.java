package com.taeho.toyprojectspring20240325.api;

import com.taeho.toyprojectspring20240325.dto.*;
import com.taeho.toyprojectspring20240325.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class MemberApiController {

    @Autowired
    private MemberService memberService;

    // 회원 가입을 의한 API
    @PostMapping("/join")
    public ResponseEntity<JoinDto> singUp
    (@RequestBody JoinForm joinForm)
    {
        JoinDto savedJoinDto = memberService.signUp(joinForm);
        return ResponseEntity.ok(savedJoinDto);
    }

    // login을 의한 API
    @PostMapping("/login")
    public ResponseEntity<JwtDto> login(@RequestBody LoginForm loginForm){
        return memberService.loginService(loginForm);
    }

    // logout을 하는 API다.
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        return memberService.logoutService(response);
    }

    // 토큰의 값을 검증하는 API다.
    // Get으로 매번 요청을 보내 토큰이 유효한지 체크한다.
    @GetMapping("/validateToken")
    public ResponseEntity<?> validateToken(HttpServletRequest request) {
        return memberService.validateTokenService(request);
    }
}
