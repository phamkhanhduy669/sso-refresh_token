package com.example.sso.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.core.GrantedAuthority;
import java.util.List;

@RestController
public class MeController {
  @GetMapping("/me")
  public UserInfoDto getUserInfo(JwtAuthenticationToken auth) {
    return new UserInfoDto(
      auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
      auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
    );
  }

  public static record UserInfoDto(String name, List<String> roles) {}
}

