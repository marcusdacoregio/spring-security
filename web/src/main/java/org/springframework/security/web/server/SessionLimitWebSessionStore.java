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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.AbstractReactivePrincipalSessionRegistry;
import org.springframework.security.core.session.InMemoryReactivePrincipalSessionRegistry;
import org.springframework.security.core.session.InvalidateLeastUsedReactiveMaximumSessionsExceededHandler;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.SessionLimit;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.InMemoryWebSessionStore;
import org.springframework.web.server.session.WebSessionStore;

public final class SessionLimitWebSessionStore implements WebSessionStore {

	private AbstractReactivePrincipalSessionRegistry principalSessionRegistry = new InMemoryReactivePrincipalSessionRegistry(
			new InvalidateLeastUsedReactiveMaximumSessionsExceededHandler());

	private WebSessionStore webSessionStore = new InMemoryWebSessionStore();

	private SessionLimit sessionLimit = SessionLimit.UNLIMITED;

	private Function<WebSession, Mono<Authentication>> authenticationResolver = new SecurityContextAttributeAuthenticationResolver();

	@Override
	public Mono<WebSession> createWebSession() {
		return this.webSessionStore.createWebSession().map(SessionLimitWebSession::new);
	}

	@Override
	public Mono<WebSession> retrieveSession(String sessionId) {
		return this.webSessionStore.retrieveSession(sessionId).map(SessionLimitWebSession::new);
	}

	@Override
	public Mono<Void> removeSession(String sessionId) {
		return this.principalSessionRegistry.removeSessionInformation(sessionId)
			.then(Mono.defer(() -> this.webSessionStore.removeSession(sessionId)));
	}

	@Override
	public Mono<WebSession> updateLastAccessTime(WebSession webSession) {
		return this.principalSessionRegistry.updateLastAccessTime(webSession.getId())
			.then(Mono.defer(() -> this.webSessionStore.updateLastAccessTime(webSession)));
	}

	public void setPrincipalSessionRegistry(AbstractReactivePrincipalSessionRegistry principalSessionRegistry) {
		this.principalSessionRegistry = principalSessionRegistry;
	}

	public void setWebSessionStore(WebSessionStore webSessionStore) {
		this.webSessionStore = webSessionStore;
	}

	public void setSessionLimit(SessionLimit sessionLimit) {
		this.sessionLimit = sessionLimit;
	}

	public void setAuthenticationResolver(Function<WebSession, Mono<Authentication>> authenticationResolver) {
		this.authenticationResolver = authenticationResolver;
	}

	class SessionLimitWebSession implements WebSession {

		private final WebSession delegate;

		SessionLimitWebSession(WebSession delegate) {
			this.delegate = delegate;
		}

		@Override
		public String getId() {
			return this.delegate.getId();
		}

		@Override
		public Map<String, Object> getAttributes() {
			return this.delegate.getAttributes();
		}

		@Override
		public void start() {
			this.delegate.start();
		}

		@Override
		public boolean isStarted() {
			return this.delegate.isStarted();
		}

		@Override
		public Mono<Void> changeSessionId() {
			return this.delegate.changeSessionId();
		}

		@Override
		public Mono<Void> invalidate() {
			return this.delegate.invalidate()
				.then(Mono.defer(() -> SessionLimitWebSessionStore.this.removeSession(getId())));
		}

		@Override
		public Mono<Void> save() {
			return SessionLimitWebSessionStore.this.authenticationResolver.apply(this)
				.flatMap(this::associatePrincipalSession)
				.then(Mono.defer(this.delegate::save));
		}

		private Mono<Void> associatePrincipalSession(Authentication authentication) {
			return SessionLimitWebSessionStore.this.sessionLimit.apply(authentication)
				.flatMap((maximumSessions) -> SessionLimitWebSessionStore.this.principalSessionRegistry.checkAndSave(
						new ReactiveSessionInformation(authentication.getPrincipal(), getId(), getLastAccessTime()),
						maximumSessions));
		}

		@Override
		public boolean isExpired() {
			return this.delegate.isExpired();
		}

		@Override
		public Instant getCreationTime() {
			return this.delegate.getCreationTime();
		}

		@Override
		public Instant getLastAccessTime() {
			return this.delegate.getLastAccessTime();
		}

		@Override
		public void setMaxIdleTime(Duration maxIdleTime) {
			this.delegate.setMaxIdleTime(maxIdleTime);
		}

		@Override
		public Duration getMaxIdleTime() {
			return this.delegate.getMaxIdleTime();
		}

	}

	static class SecurityContextAttributeAuthenticationResolver implements Function<WebSession, Mono<Authentication>> {

		private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

		@Override
		public Mono<Authentication> apply(WebSession session) {
			SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
			if (securityContext == null || securityContext.getAuthentication() == null
					|| this.trustResolver.isAnonymous(securityContext.getAuthentication())) {
				return Mono.empty();
			}
			return Mono.just(securityContext.getAuthentication());
		}

	}

}
