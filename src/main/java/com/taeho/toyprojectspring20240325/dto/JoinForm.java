package com.taeho.toyprojectspring20240325.dto;

import com.taeho.toyprojectspring20240325.entity.Member;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
// 웹 페이지에서 사용자가 보내는 회원 가입 정보를 불러온다.
public class JoinForm {
    private String username;
    private String schoolname;
    private String userid;
    private String password;
    private List<String> roles = new ArrayList<>();

    public Member toEntity(String encodedPassword, List<String> roles) {

        return Member.builder()
                .username(username)
                .userid(userid)
                .password(encodedPassword)
                .shcoolname(schoolname)
                .roles(roles)
                .build();
    }
}
