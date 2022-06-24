package com.rubypaper.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private BoardUserDetailsService boardUserDetailsService;

	@Override
	protected void configure(HttpSecurity security) throws Exception {
		//417. 실습2 시큐리티 재정의
		security.authorizeRequests().antMatchers("/").permitAll();
		security.authorizeRequests().antMatchers("/member/**").authenticated();
		security.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER");
		security.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
		security.csrf().disable();

		//420. 실습3. 사용자 인증.에러 발생이 아니라 로그인 화면으로 이동
		//security.formLogin();
		
		//420. 실습4. 사용자 로그인 화면으로 이동
		security.formLogin().loginPage("/login").defaultSuccessUrl("/loginSuccess", true);

		//428. 실습6. 접근 권한 요청 없을 때 처리
		security.exceptionHandling().accessDeniedPage("/accessDenied");

		//430. 실습7. 로그아웃
		security.logout().invalidateHttpSession(true).logoutSuccessUrl("/login");

		//448. 사용자정의 서비스 적용
		security.userDetailsService(boardUserDetailsService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

}
