package com.example.idp.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/SingleSignOnService")
public class SingleSignOnController {
    @Value("${sp.base_url}")
    private String spBaseUrl;

    @GetMapping
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        log.info("AuthnRequest recieved");
        // todo 解析AuthnRequest
        doPost(req, resp);
    }

    @PostMapping
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        resp.sendRedirect(spBaseUrl + "/sp/consumer" + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
    }


}
