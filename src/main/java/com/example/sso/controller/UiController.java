package com.example.sso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.util.Objects;

@Controller
public class UiController {
  @GetMapping("/")
  public String getIndex(Model model, Authentication auth) {
    model.addAttribute("name",
        auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidc
        ? oidc.getPreferredUsername()
        : "");
    model.addAttribute("isAuthenticated",
        auth != null && auth.isAuthenticated());
    model.addAttribute("isNice", 
        auth != null && auth.getAuthorities().stream().anyMatch(authority -> {
          return Objects.equals("NICE", authority.getAuthority());
        }));
    return "index.html";
  }
  
  @GetMapping("/nice")
  public String getNice(Model model, Authentication auth) {
    return "nice.html";
  }
  
  @GetMapping("/login")
  public String getLogin() {
    return "redirect:/";
  }
  
  @GetMapping("/profile")
  public String getProfile(Model model, Authentication auth) {
    if (auth == null || !auth.isAuthenticated()) {
      return "redirect:/login";
    }
    
    if (auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidc) {
      model.addAttribute("name", oidc.getPreferredUsername());
      model.addAttribute("email", oidc.getEmail());
      model.addAttribute("fullName", oidc.getFullName());
      model.addAttribute("givenName", oidc.getGivenName());
      model.addAttribute("familyName", oidc.getFamilyName());
      model.addAttribute("roles", auth.getAuthorities());
    }
    return "profile";
  }
}