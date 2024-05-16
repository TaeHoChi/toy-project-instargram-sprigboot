package com.taeho.toyprojectspring20240325.dto;

import com.taeho.toyprojectspring20240325.entity.Member;
import lombok.AllArgsConstructor;
import lombok.*;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
// 웹 사이트에서 보낸 사용자 정보(JoinForm)를 JoinDto에 담아서 DB에 보낸다.
public class JoinDto {
    private Long numberid;
    private String username;
    private String schoolname;
    private String userid;
    private String password;

    static public JoinDto toDto(Member member) {
        return JoinDto.builder()
                .numberid(member.getNumberid())
                .username(member.getUsername())
                .schoolname(member.getShcoolname())
                .userid(member.getUserid())
                .password(member.getPassword()).build();
    }

    public Member toEntity() {
        return Member.builder()
                .numberid(numberid)
                .username(username)
                .shcoolname(schoolname)
                .userid(userid)
                .password(password)
                .build();
    }

}
