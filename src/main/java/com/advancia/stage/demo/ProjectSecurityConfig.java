package com.advancia.stage.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
public class ProjectSecurityConfig {
	
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

		CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
		
		requestHandler.setCsrfRequestAttributeName("_csrf");
		
        http
        .securityContext(securityContext -> 
            securityContext.requireExplicitSave(false))
        .sessionManagement(session -> 
            session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
        .csrf(csrf -> 
            csrf.csrfTokenRequestHandler(requestHandler)
                .ignoringRequestMatchers("/contact", "/register")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/myAccount").hasRole("USER")
            .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
            .requestMatchers("/myLoans").hasRole("USER")
            .requestMatchers("/myCards").hasRole("USER")
            .requestMatchers("/user").authenticated()
            .anyRequest().permitAll())
        .formLogin()
        .and()
        .httpBasic();

    return http.build();
}
	
	
	
	/*
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests().requestMatchers("/myAccount","/myBalance", "/myLoans", "/myCards").authenticated()
		.requestMatchers("/notices","/contact").permitAll()
		.and().formLogin()
		.and().httpBasic();
		
		return http.build();
		
	}
	

	*/
	
	
	
	/*
	 		RIFIUTA TUTTE LE RICHIESTE

 		http.authorizeHttpRequests().anyRequestes().denyAll()
		.and().formLogin()
		.and().httpBasic();
		
		return http.build();
		
		
		
		PERMETTI TUTTE
		
				http.authorizeHttpRequests().anyRequest().permitAll()
		.and().formLogin()
		.and().httpBasic();
		
		return http.build();
 
 
	 
	 */

}
