package com.taeho.toyprojectspring20240325.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@ToString
@Getter
@Setter
// 인자 없는 생성자를 생성. 외부에서 생성을 제한하고 JPA에서만 사용하도록 설정
@NoArgsConstructor
// 모든 필드 값을 인자로 받는 생성자를 자동 생성
@AllArgsConstructor
// 빌더 패턴을 사용할 수 있게 해주는 Lombok 어노테이션
@Builder
public class Board {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long numberid;



}
