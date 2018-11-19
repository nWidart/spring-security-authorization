package com.example.authorization;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class AuthorizationApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthorizationApplication.class, args);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}

@Configuration
@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.httpBasic();

    http
        .authorizeRequests()
        .mvcMatchers("/root").hasAnyAuthority("ROLE_ADMIN")
        .mvcMatchers(HttpMethod.GET, "/a").access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();

//    http
//        .authorizeRequests().anyRequest().authenticated();
  }
}

@RestController
class RootRestController {

  @GetMapping("/root")
  public String root() {
    return "root";
  }
}

@RestController
class LetterRestController {

  @GetMapping("/a")
  public String a() {
    return "a";
  }

  @GetMapping("/b")
  public String b() {
    return "b";
  }

  @GetMapping("/c")
  public String c() {
    return "c";
  }
}

@RestController
class UserRestController {

  @GetMapping("/users/{name}")
  public String userByName(@PathVariable String name) {
    return "user: " + name;
  }
}

@Service
class CustomUserDetailsService implements UserDetailsService {

  private final Map<String, UserDetails> users = new HashMap<>();

  public CustomUserDetailsService() {
    this.users.put("nwidart", new CustomUser("nwidart", "password", true, "USER"));
    this.users.put("jlong", new CustomUser("jlong", "password", true, "USER", "ADMIN"));
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    if (!this.users.containsKey(username)) {
      throw new UsernameNotFoundException("cant find username");
    }
    return this.users.get(username);
  }
}

class CustomUser implements UserDetails {

  private final Set<GrantedAuthority> authorities = new HashSet<>();
  private final String username, password;
  private final boolean active;

  CustomUser(String username, String password, boolean active, String... authorities) {
    this.username = username;
    this.password = password;
    this.active = active;

    this.authorities.addAll(Arrays.stream(authorities)
        .map(s -> new SimpleGrantedAuthority("ROLE_" + s))
        .collect(Collectors.toSet()));
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return this.authorities;
  }

  @Override
  public String getPassword() {
    return this.password;
  }

  @Override
  public String getUsername() {
    return this.username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return false;
  }

  @Override
  public boolean isAccountNonLocked() {
    return this.active;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return this.active;
  }

  @Override
  public boolean isEnabled() {
    return this.active;
  }
}
