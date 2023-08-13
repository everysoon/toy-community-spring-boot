package com.soon.sociallogin.config.security;

import com.soon.sociallogin.config.handler.CustomAuthenticationFailureHandler;
import com.soon.sociallogin.config.handler.CustomAuthenticationSuccessHandler;
import com.soon.sociallogin.config.handler.UserServiceHandler;
import com.soon.sociallogin.config.security.jwt.JwtManager;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityConfig {
    private final UserServiceHandler userServiceHandler;
//    private final InMemoryClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    //    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        /**
//         * AuthenticationManager (인증 처리 manager) 에서 authenticate 메소드 통해 인증 처리시
//         * Custom 한 UserServiceHandler, PasswordEncoder 사용 하겠다는 의미
//         **/
//        auth.userDetailsService(userServiceHandler).passwordEncoder(passwordEncoder());
//    }
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthorizationRequestRepository<OAuth2AuthorizationRequest> httpSessionOAuth2AuthorizationRequestRepository,
//                                           AuthorizationRequestRepository<OAuth2AuthorizationRequest> requestAuthorizationRequestRepository,
                                           AuthenticationSuccessHandler authenticationSuccessHandler,
                                           AuthenticationFailureHandler authenticationFailureHandler,
                                           OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService) throws Exception {
        http
                .sessionManagement(c ->
                        /**
                         *  stateless로 개발(모든요청이 세션의 의존적이지 않은 독립적)
                         * 세션이 아닌 jwt로 할꺼라!
                         * **/
                        c.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic(AbstractHttpConfigurer::disable) // basic authentication filter 비활성화

                .formLogin(AbstractHttpConfigurer::disable) // formlogin,logout,httpBasic 비 활성화 - jwt로 개발할거라
                .logout(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable) // csrf diabled
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(
                                    new AntPathRequestMatcher("/oauth2/**"),
                                    new AntPathRequestMatcher("/login/oauth2/code/**"),
                                    new AntPathRequestMatcher("/auth/**")
                            ).permitAll()
                            .anyRequest().authenticated();
                })
                .oauth2Login(
                        auth ->
                        auth
                                .authorizationEndpoint(config ->
                                        config
                                                .baseUri("/login/oauth2/code")
                                                .authorizationRequestRepository(httpSessionOAuth2AuthorizationRequestRepository)

                                )

//                                .clientRegistrationRepository(clientRegistrationRepository)
                                .redirectionEndpoint(config -> config.baseUri("/login/oauth2/callback/*"))
                                .userInfoEndpoint(config -> config.userService(oAuth2UserService))

//                                .authorizedClientRepository(authorizedClientRepository)
//                                .authorizedClientService(authorizedClientService)
                                .successHandler(authenticationSuccessHandler)
                                .failureHandler(authenticationFailureHandler)

                )
                .exceptionHandling(eh ->
                        eh.authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendError(401))
                                .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendError(403))
                );


        return http.build();
    }



    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> httpSessionOAuth2AuthorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(new JwtManager(userServiceHandler));
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new com.soon.sociallogin.config.oauth2.OAuth2UserService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}