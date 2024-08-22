package admin_user.configurations;

import java.lang.management.PlatformManagedObject;

import org.apache.coyote.http11.Http11InputBuffer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.session.RedisSessionProperties.ConfigureAction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.FormLoginBeanDefinitionParser;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

import admin_user.service.CustomSuccessHandler;
import admin_user.service.CustomUserDetailService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired
	CustomSuccessHandler customSuccessHandler;
	@Autowired
	CustomUserDetailService customUserDetailService;
	
	@Bean
	public static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
    @Bean 
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    	
    	http.csrf(c -> c.disable())
    	
    	.authorizeHttpRequests(request -> request
    			.requestMatchers("/admin-page")
    	         .hasAuthority("ADMIN")
    	         .requestMatchers("/user-page")
    	         .hasAuthority("USER")
    	         .requestMatchers("/registration", "/css/**", "/js/**", "/fonts/**", "/img/**")
    	         .permitAll()
    	         .anyRequest().authenticated())

    	.formLogin(form -> form
    			.loginPage("/login")
    			.loginProcessingUrl("/login")
    	         .successHandler(customSuccessHandler)
    	         .permitAll())
    	
    	.logout(form -> form
    			.invalidateHttpSession(true)
    			.clearAuthentication(true)
    			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
    			.logoutSuccessUrl("/login?logout")
    			.permitAll());
    	
    	return http.build();

    }
    
    @Autowired
    public void configure (AuthenticationManagerBuilder auth) throws Exception {
    	auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder());
    }

}
