/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.session.AbstractReactivePrincipalSessionRegistry;
import org.springframework.security.core.session.InMemoryReactivePrincipalSessionRegistry;
import org.springframework.security.core.session.ReactiveMaximumSessionsExceededHandler;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.WebSessionStore;

public final class WebSessionPrincipalSessionRegistry extends AbstractReactivePrincipalSessionRegistry {

	private final WebSessionStore webSessionStore;

	private AbstractReactivePrincipalSessionRegistry principalSessionRegistry;

	public WebSessionPrincipalSessionRegistry(ReactiveMaximumSessionsExceededHandler maximumSessionsExceededHandler,
			WebSessionStore webSessionStore) {
		super(maximumSessionsExceededHandler);
		this.principalSessionRegistry = new InMemoryReactivePrincipalSessionRegistry(maximumSessionsExceededHandler);
		this.webSessionStore = webSessionStore;
	}

	@Override
	public Flux<ReactiveSessionInformation> getPrincipalSessions(Object principal) {
		return this.principalSessionRegistry.getPrincipalSessions(principal).map(WebSessionInformation::new);
	}

	@Override
	public Mono<ReactiveSessionInformation> removeSessionInformation(String sessionId) {
		return this.principalSessionRegistry.removeSessionInformation(sessionId).map(WebSessionInformation::new);
	}

	@Override
	public Mono<ReactiveSessionInformation> updateLastAccessTime(String sessionId) {
		return this.principalSessionRegistry.updateLastAccessTime(sessionId).map(WebSessionInformation::new);
	}

	@Override
	public Mono<Void> saveSessionInformation(ReactiveSessionInformation sessionInformation) {
		return this.principalSessionRegistry.saveSessionInformation(sessionInformation);
	}

	final class WebSessionInformation extends ReactiveSessionInformation {

		WebSessionInformation(ReactiveSessionInformation sessionInformation) {
			super(sessionInformation.getPrincipal(), sessionInformation.getSessionId(),
					sessionInformation.getLastAccessTime());
		}

		@Override
		public Mono<Void> invalidate() {
			return WebSessionPrincipalSessionRegistry.this.webSessionStore.retrieveSession(getSessionId())
				.flatMap(WebSession::invalidate)
				.then(Mono
					.defer(() -> WebSessionPrincipalSessionRegistry.this.removeSessionInformation(getSessionId())))
				.then(Mono.defer(super::invalidate));
		}

	}

}
