package com.danjitalk.danjitalk.application.oauth;

import com.danjitalk.danjitalk.common.security.CustomMemberDetails;
import com.danjitalk.danjitalk.domain.user.member.entity.SystemUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {

        String state = request.getParameter("state");
        log.info("state: {}", state);
        String redisKey = "oauth2:temp:state:" + state;

        String origin = (String) redisTemplate.opsForValue().get(redisKey);
        log.info("origin: {}", origin);
//        redisTemplate.delete(redisKey); // 굳이?

        String redirectUri;
        if (origin != null) {
            redirectUri = origin;
        } else {
            redirectUri = "https://danji-talk-frontend.vercel.app";
        }

        // OAuth2 로그인이 성공했을 때의 추가 작업을 수행
        // 여기에서는 JWT 토큰을 발급하고 형식에 맞게 return
        CustomMemberDetails customMemberDetails = (CustomMemberDetails) authentication.getPrincipal();
        SystemUser user = customMemberDetails.getUser();
        String uuid = UUID.randomUUID().toString();

        Map<String, Object> map = new HashMap<>();
        map.put("memberId", user.getSystemUserId());
        map.put("memberEmail", user.getLoginId());
        map.put("provider", user.getLastLoginMethod());

        String key = "jwt:temp:claim:" + uuid;

        redisTemplate.opsForValue().set(key, map, Duration.ofMinutes(3));

        // 성공 후 리다이렉트 SecurityConfig에 .defaultSuccessUrl("/api/success/oauth")는 쿠키설정이 안됨
        getRedirectStrategy().sendRedirect(request, response, redirectUri + "/oauth/redirect?status=success&social-code=" + uuid); // 리다이렉트 주소
    }
}
