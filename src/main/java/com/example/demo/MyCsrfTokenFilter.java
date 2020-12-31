package com.example.demo;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

public class MyCsrfTokenFilter extends OncePerRequestFilter {

  private final HttpSessionCsrfTokenRepository csrfTokenRepository;

  public MyCsrfTokenFilter(HttpSessionCsrfTokenRepository csrfTokenRepository) {
    this.csrfTokenRepository = csrfTokenRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    CsrfToken beforeToken = this.csrfTokenRepository.loadToken(request);

    if (beforeToken != null) {
      this.csrfTokenRepository.saveToken(null, request, response);
      CsrfToken csrfToken = this.csrfTokenRepository.generateToken(request);
      this.csrfTokenRepository.saveToken(csrfToken, request, response);
      request.setAttribute(CsrfToken.class.getName(), csrfToken);
      request.setAttribute(csrfToken.getParameterName(), csrfToken);
    }

    filterChain.doFilter(request, response);
  }
}
