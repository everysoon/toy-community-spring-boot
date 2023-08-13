package com.soon.sociallogin.service;

import com.soon.sociallogin.domain.User;
import com.soon.sociallogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User findById(Long userId){
        return userRepository.findById(userId).orElse(null);
    }
    public User findBySocialId(String socialId){
        return userRepository.findBySocialId(socialId).orElse(null);
    }
}
