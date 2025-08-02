package com.danjitalk.danjitalk.application.user.member;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {

        String redirectUri;

        String origin = request.getHeader("Origin");
        log.info("origin: {}", origin);

        if (origin != null) {
            redirectUri = origin + "/login";
        } else {
            redirectUri = "https://danji-talk-frontend.vercel.app/login";
        }

        response.sendRedirect(redirectUri);
    }
}