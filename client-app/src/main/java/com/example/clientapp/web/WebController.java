package com.example.clientapp.web;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class WebController {
  @GetMapping("/") public String index(){ return "index"; }
  @GetMapping("/me") public String me(@AuthenticationPrincipal OidcUser user, Model model){ model.addAttribute("claims", user.getClaims()); return "me"; }
}
