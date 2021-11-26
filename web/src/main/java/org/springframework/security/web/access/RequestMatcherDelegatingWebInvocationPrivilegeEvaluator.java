/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.access;

import java.util.List;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;

/**
 * A {@link WebInvocationPrivilegeEvaluator} which delegates to a
 * {@link WebInvocationPrivilegeEvaluator} based on a
 * {@link org.springframework.security.web.util.matcher.RequestMatcher}
 *
 * @author Marcus Da Coregio
 * @since 5.7
 */
public final class RequestMatcherDelegatingWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

	private final List<RequestMatcherPrivilegeEvaluator> delegates;

	public RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
			List<RequestMatcherPrivilegeEvaluator> requestMatcherPrivilegeEvaluators) {
		Assert.notNull(requestMatcherPrivilegeEvaluators, "requestMatcherPrivilegeEvaluators cannot be null");
		this.delegates = requestMatcherPrivilegeEvaluators;
	}

	/**
	 * Determines whether the user represented by the supplied <tt>Authentication</tt>
	 * object is allowed to invoke the supplied URI.
	 * <p>
	 * Tries to match the provided URI against the
	 * {@link SecurityFilterChain#matches(HttpServletRequest)} for every
	 * {@code SecurityFilterChain} configured. If no {@code SecurityFilterChain} is found,
	 * or there is not a {@code WebInvocationPrivilegeEvaluator} for the
	 * {@code SecurityFilterChain}, returns {@code true}.
	 * @param uri the URI excluding the context path (a default context path setting will
	 * be used)
	 * @return true if access is allowed, false if denied
	 */
	@Override
	public boolean isAllowed(String uri, Authentication authentication) {
		return isAllowed(null, uri, null, authentication);
	}

	/**
	 * Determines whether the user represented by the supplied <tt>Authentication</tt>
	 * object is allowed to invoke the supplied URI.
	 * <p>
	 * Tries to match the provided URI against the
	 * {@link SecurityFilterChain#matches(HttpServletRequest)} for every
	 * {@link SecurityFilterChain} configured. If no {@code SecurityFilterChain} is found,
	 * or there is not a {@code WebInvocationPrivilegeEvaluator} for the
	 * {@code SecurityFilterChain}, returns {@code true}.
	 * @param uri the URI excluding the context path (a default context path setting will
	 * be used)
	 * @param contextPath the context path (may be null, in which case a default value
	 * will be used).
	 * @param method the HTTP method (or null, for any method)
	 * @param authentication the <tt>Authentication</tt> instance whose authorities should
	 * be used in evaluation whether access should be granted.
	 * @return true if access is allowed, false if denied
	 */
	@Override
	public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
		RequestMatcherPrivilegeEvaluator delegate = getDelegate(contextPath, uri, method);
		if (delegate == null) {
			return true;
		}
		WebInvocationPrivilegeEvaluator privilegeEvaluator = delegate.getPrivilegeEvaluator();
		if (privilegeEvaluator == null) {
			return true;
		}
		return privilegeEvaluator.isAllowed(contextPath, uri, method, authentication);
	}

	private RequestMatcherPrivilegeEvaluator getDelegate(String contextPath, String uri, String method) {
		FilterInvocation filterInvocation = new FilterInvocation(contextPath, uri, method);
		for (RequestMatcherPrivilegeEvaluator delegate : this.delegates) {
			if (delegate.matches(filterInvocation.getHttpRequest())) {
				return delegate;
			}
		}
		return null;
	}

	public static class RequestMatcherPrivilegeEvaluator {

		private final Function<HttpServletRequest, Boolean> requestMatcher;

		private final WebInvocationPrivilegeEvaluator privilegeEvaluator;

		public RequestMatcherPrivilegeEvaluator(Function<HttpServletRequest, Boolean> requestMatcher,
				WebInvocationPrivilegeEvaluator privilegeEvaluator) {
			Assert.notNull(requestMatcher, "requestMatcher cannot be null");
			this.requestMatcher = requestMatcher;
			this.privilegeEvaluator = privilegeEvaluator;
		}

		public boolean matches(HttpServletRequest request) {
			return this.requestMatcher.apply(request);
		}

		public WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() {
			return this.privilegeEvaluator;
		}

	}

}
