package com.soon.sociallogin.controller;

import com.soon.sociallogin.config.security.UserAdapter;
import com.soon.sociallogin.config.security.jwt.JwtManager;
import com.soon.sociallogin.config.security.jwt.Token;
import com.soon.sociallogin.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@RequestMapping
@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

//    @GetMapping("/auth")
//    public void auth(
//            @RequestParam("access_token") String accessToken,
//            @RequestParam("refresh_token") String refreshToken,
//            @AuthenticationPrincipal UserAdapter userAdapter,
//            @RequestParam("authentication") Authentication authentication,
//            HttpServletRequest request,
//            HttpServletResponse response) throws IOException {
//        log.info(accessToken);
//        log.info(refreshToken);
//        log.info(authentication.toString());
//        log.info(userAdapter.toString());
//
//        authService.login(authentication,response);
//    }

    @PostMapping("/authorize")
    public ResponseEntity<?> auth(@AuthenticationPrincipal UserAdapter userAdapter) {
        return ResponseEntity.ok(userAdapter.getUsername());
    }

}
