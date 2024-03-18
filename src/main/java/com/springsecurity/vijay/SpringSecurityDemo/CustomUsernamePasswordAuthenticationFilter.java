package com.springsecurity.vijay.SpringSecurityDemo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/*import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;*/
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter
{

	/*
	 * (non-Javadoc)
	 * @see
	 * org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter#attemptAuthentication(javax
	 * .servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
												HttpServletResponse response)
	{
		if (!request.getMethod().equals("POST"))
		{
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		String username = obtainUsername(request);
		String password = obtainPassword(request);
		System.out.println("Vijay in  CustomUsernamePasswordAuthenticationFilter");

		username = username.trim();

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

		// Place the last username attempted into HttpSession for views
		HttpSession session = request.getSession(false);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
		CustomAuthenticationManager authenticationManager = (CustomAuthenticationManager)getAuthenticationManager();
		// Necessary pass the request to the Authentication Manager in order to get the hostName and store the
		// UserContext at the session;
		//authenticationManager.setServletRequest(request);
		return authenticationManager.authenticate(authRequest);
	}



}
