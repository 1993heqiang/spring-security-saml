/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.sp.component;

import java.io.IOException;
import java.util.*;


import org.springframework.core.annotation.Order;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.example.sp.config.SecurityConfiguration.DEFAULT_REGISTRATION_ID;

@Component
@Order(-101) // To run before FilterChainProxy
public class SamlExtensionUrlForwardingFilter extends OncePerRequestFilter {

    // @formatter:off
	private static final Map<String, String> URL_MAPPING;
	// @formatter:on

    static {
        Map<String, String> presetData = new HashMap<>();
        presetData.put("/saml/SSO", "/login/saml2/sso/" + DEFAULT_REGISTRATION_ID);
        presetData.put("/saml/login", "/saml2/authenticate/" + DEFAULT_REGISTRATION_ID);
        presetData.put("/saml/logout", "/logout/saml2/slo");
        presetData.put("/saml/SingleLogout", "/logout/saml2/slo");
        presetData.put("/saml/metadata", "/saml2/service-provider-metadata/" + DEFAULT_REGISTRATION_ID);
        URL_MAPPING = Collections.unmodifiableMap(presetData);
    }

    private final RequestMatcher matcher = createRequestMatcher();

    private RequestMatcher createRequestMatcher() {
        Set<String> urls = URL_MAPPING.keySet();
        List<RequestMatcher> matchers = new LinkedList<>();
        urls.forEach((url) -> matchers.add(new AntPathRequestMatcher(url)));
        return new OrRequestMatcher(matchers);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        boolean match = this.matcher.matches(request);
        if (!match) {
            filterChain.doFilter(request, response);
            return;
        }
        String forwardUrl = URL_MAPPING.get(request.getRequestURI());
        RequestDispatcher dispatcher = request.getRequestDispatcher(forwardUrl);
        dispatcher.forward(request, response);
    }

}
