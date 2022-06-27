/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.aot.hint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsPredicates;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.core.annotation.SynthesizedAnnotation;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link GlobalMethodSecurityHints}
 *
 * @author Marcus Da Coregio
 */
class GlobalMethodSecurityHintsTests {

	private final RuntimeHints hints = new RuntimeHints();

	@BeforeEach
	void setup() {
		SpringFactoriesLoader.forResourceLocation("META-INF/spring/aot.factories").load(RuntimeHintsRegistrar.class)
				.forEach((registrar) -> registrar.registerHints(this.hints, ClassUtils.getDefaultClassLoader()));
	}

	@Test
	void enableGlobalAuthenticationHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(EnableGlobalAuthentication.class)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS)).accepts(this.hints);
		assertThat(RuntimeHintsPredicates.proxies().forInterfaces(EnableGlobalAuthentication.class,
				SynthesizedAnnotation.class)).accepts(this.hints);
	}

}
