package com.taeho.toyprojectspring20240325.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

// 토큰을 생성해서 값을 가지고 있을 DTO 클래스를 정의한다.
// 클라이언트에 토큰을 보내기 위해 JwtToken DTO를 생성한다.
// grantType는 JWT에 대한 인증 타입이다.
@Builder
@Data
@AllArgsConstructor
public class JwtDto {
    private String grantType;
    private String accessToken;
    private String refreshToken;

}
