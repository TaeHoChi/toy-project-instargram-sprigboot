package com.taeho.toyprojectspring20240325.repository;

import com.taeho.toyprojectspring20240325.dto.JoinForm;
import com.taeho.toyprojectspring20240325.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;


// 회원 가입에 필요한 Respository다.
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUserid(String user);

    Boolean existsByUserid(String JoinForm);

}
