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

import java.util.Arrays;
import java.util.Collections;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link RequestMatcherDelegatingWebInvocationPrivilegeEvaluator}
 *
 * @author Marcus Da Coregio
 */
class RequestMatcherDelegatingWebInvocationPrivilegeEvaluatorTests {

	private final Function<HttpServletRequest, Boolean> alwaysMatch = (request) -> true;

	private final String uri = "/test";

	private final Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

	@Test
	void isAllowedWhenDelegatesEmptyThenAllowed() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.emptyList());
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenNotMatchThenAllowed() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator notMatch = mock(
				RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator.class);
		given(notMatch.matches(any())).willReturn(false);
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(notMatch));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(notMatch).matches(any());
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorAllowThenAllowedTrue() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator delegate = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator(
				this.alwaysMatch, TestWebInvocationPrivilegeEvaluator.alwaysAllow());
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorDenyThenAllowedFalse() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator delegate = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator(
				this.alwaysMatch, TestWebInvocationPrivilegeEvaluator.alwaysDeny());
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
	}

	@Test
	void isAllowedWhenNotMatchThenMatchThenOnlySecondDelegateInvoked() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator notMatchDelegate = mock(
				RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator.class);
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator matchDelegate = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator(
				this.alwaysMatch, TestWebInvocationPrivilegeEvaluator.alwaysAllow());
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator spyMatchDelegate = spy(
				matchDelegate);
		given(notMatchDelegate.matches(any())).willReturn(false);

		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Arrays.asList(notMatchDelegate, spyMatchDelegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(notMatchDelegate).matches(any());
		verify(notMatchDelegate, never()).getPrivilegeEvaluator();
		verify(spyMatchDelegate).matches(any());
		verify(spyMatchDelegate).getPrivilegeEvaluator();
	}

	@Test
	void isAllowedWhenDelegatePrivilegeEvaluatorNullThenAllowedTrue() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator delegate = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator.RequestMatcherPrivilegeEvaluator(
				this.alwaysMatch, null);
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

}
