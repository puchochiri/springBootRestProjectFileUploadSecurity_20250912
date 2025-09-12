package org.puchori.springbootproject.config;



import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.Security;

@Log4j2
@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomSecurityConfig {

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    log.info("-----------------configure-------------");

    http
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/css/**", "/js/**", "images/**").permitAll() // 정적 리소스 혀용
          .anyRequest().authenticated() // 나머지는 인증필요
        )
      .formLogin(form -> form
              .loginPage("/member/login")
              .defaultSuccessUrl("/")
              .permitAll()
      )
      .logout(Customizer.withDefaults());



    //http.formLogin();

    return http.build();

  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    log.info("------------- web configure-------------------");

    return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
  }





}
