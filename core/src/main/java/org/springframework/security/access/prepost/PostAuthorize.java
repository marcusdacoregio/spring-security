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

package org.springframework.security.access.prepost;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;

/**
 * Annotation for specifying a method access-control expression which will be evaluated
 * after a method has been invoked.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use {@link org.springframework.security.authorization.method.PostAuthorize}
 * instead
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Deprecated(since = "6.3", forRemoval = true)
@org.springframework.security.authorization.method.PostAuthorize(value = "")
public @interface PostAuthorize {

	/**
	 * @return the Spring-EL expression to be evaluated after invoking the protected
	 * method
	 */
	@AliasFor(attribute = "value", annotation = org.springframework.security.authorization.method.PostAuthorize.class)
	String value();

}
