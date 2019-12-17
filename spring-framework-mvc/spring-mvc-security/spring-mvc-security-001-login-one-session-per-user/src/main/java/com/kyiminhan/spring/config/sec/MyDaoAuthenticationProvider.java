package com.kyiminhan.spring.config.sec;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyDaoAuthenticationProvider extends DaoAuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (StringUtils.isBlank(authentication.getName())) {

			throw new UsernameNotFoundException("Email is required.");

		} else if (!ObjectUtils.anyNotNull(authentication.getCredentials())
				| StringUtils.isBlank(authentication.getCredentials().toString())) {

			throw new BadCredentialsException("Password is required.");

		} else {

			try {

				return super.authenticate(authentication);

			} catch (final BadCredentialsException e) {

				throw new BadCredentialsException("Invalid email and password.");
			}
		}
	}
}
