package com.soon.sociallogin.repository;

import com.soon.sociallogin.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findById(Long id);
    Optional<User> findBySocialId(String socialId);
}
