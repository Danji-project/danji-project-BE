package com.danjitalk.danjitalk.application.oauth;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;
    private final RedisTemplate<String, Object> redisTemplate;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository repo, RedisTemplate<String, Object> redisTemplate) {
        log.info("CustomAuthorizationRequestResolver");
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");
        this.redisTemplate = redisTemplate;
    }

    // 소셜로그인 과정에서 둘 중 하나만 실행
    // 주로 클라이언트 식별자(clientRegistrationId)가 HTTP 요청 URL 경로에 포함되어 있고, 별도로 ID를 명시하지 않는 경우 호출됩니다.
    // 예를 들어 /oauth2/authorization/kakao처럼 URL로 요청할 때.
    // 똑같은 resolve 두 번 호출함 기본적으로 이거 호출하는듯
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        log.info("resolve(request) called: URI = {}", request.getRequestURI());
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);
        return customize(req, request);
    }

    //클라이언트 ID를 명확히 알고 있을 때(프로그래밍적으로 명시적으로 호출할 때) 사용
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        log.info("resolve(request, clientRegistrationId) called: URI = {}", request.getRequestURI());
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request, clientRegistrationId);
        return customize(req, request);
    }

    private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest req, HttpServletRequest request) {
        log.info("customize");
        if (req == null) { // /oauth2/authorization/kakao가 아니면 즉 (/login/oauth2/code/kakao)면 req가 null임
            return null;    // resolveRegistrationId가 /oauth2/authorization가 아니면 null 반환하게 함
        }

        String origin = getOrigin(request);
        log.info("origin = {}", origin);

        log.info("req.getState() = {}", req.getState());
        String state = req.getState();
        String redisKey = "oauth2:temp:state:" + state;
        redisTemplate.opsForValue().set(redisKey, origin, Duration.ofMinutes(3));

        return req;
    }

    private String getOrigin(HttpServletRequest request) {
        // 1. 쿼리스트링 방식
        String queryOrigin = request.getParameter("origin");
        log.info("Raw query string: {}", request.getQueryString());
        if (queryOrigin != null) {
            log.info("queryOrigin: {}", queryOrigin);
            return queryOrigin;
        }

        // 도메인 달라서 불가능한듯
//        // 2. 쿠키 방식
//        if (request.getCookies() != null) {
//            for (Cookie cookie : request.getCookies()) {
//                if ("origin".equals(cookie.getName())) {
//                    log.info("CookieOrigin: {}", cookie.getValue());
//                    return cookie.getValue();
//                }
//            }
//        }

        return null;
    }
}