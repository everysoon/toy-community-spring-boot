package com.soon.sociallogin.config.security.jwt;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;
import java.time.LocalDateTime;

@Getter
@Builder
public class Token {
    private String accessToken;
    private String refreshToken;
    private Duration expiredAccess;
    private Duration expiredRefresh;
}
