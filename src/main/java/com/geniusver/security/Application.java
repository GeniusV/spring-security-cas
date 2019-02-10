package com.geniusver.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by GeniusV on 2019-02-10.
 */
@RestController
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping("/hello")
    public String hello() {
        return "hello";
    }

    @PreAuthorize("hasAuthority('test')")
    @RequestMapping("/test")
    public String security() {
        return "test authority";
    }

    @PreAuthorize("hasAuthority('ADMIN')")//必须要有ADMIN权限的才能访问
    @RequestMapping("/admin")
    public String authorize() {
        return "admin authority";
    }

}
