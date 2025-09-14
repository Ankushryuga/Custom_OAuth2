package com.example.authserver.web;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    /** Serve the compiled React app (placed under /static/login by the Dockerfile) */
    @GetMapping("/login")
    public String login() { return "forward:/login/index.html"; }
}
