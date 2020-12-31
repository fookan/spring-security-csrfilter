package com.example.demo;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Autowired
  private DataSource dataSource;

  private static final String USER_SQL = ""
    + " SELECT"
    + "  user_id,"
    + "  password,"
    + "  enabled"
    + " FROM"
    + "  m_user"
    + " WHERE"
    + "  user_id = ?";

  private static final String ROLE_SQL = ""
    + " SELECT"
    + "  m_user.user_id,"
    + "  role.role_name"
    + " FROM"
    + "  m_user INNER JOIN t_user_role AS user_role"
    + " ON"
    + "  m_user.user_id = user_role.user_id"
    + " INNER JOIN m_role AS role"
    + " ON"
    + "  user_role.role_id = role.role_id"
    + " WHERE"
    + "  m_user.user_id = ?";

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    final HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();

    http
      .authorizeRequests()
        .antMatchers("/login").permitAll()
        .anyRequest().authenticated();

    http
      .formLogin()
        .loginProcessingUrl("/login")
        .loginPage("/login")
        .failureUrl("/login?error")
        .usernameParameter("userId")
        .passwordParameter("password")
        .defaultSuccessUrl("/home", true);

    http
      .logout()
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login");

    http
      .csrf().csrfTokenRepository(repository)
      .and()
      .addFilterAfter(new MyCsrfTokenFilter(repository), CsrfFilter.class);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.jdbcAuthentication()
      .dataSource(dataSource)
      .usersByUsernameQuery(USER_SQL)
      .authoritiesByUsernameQuery(ROLE_SQL)
      .passwordEncoder(passwordEncoder());
  }
}
