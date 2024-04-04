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

package org.springframework.security.config.annotation.method.configuration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedPostProcessor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.util.StringUtils;

/**
 * @author Rob Winch
 */
@MethodSecurityService.Mask("classmask")
public interface MethodSecurityService {

	@PreAuthorize("denyAll")
	String preAuthorize();

	@Secured("ROLE_ADMIN")
	String secured();

	@Secured("ROLE_USER")
	String securedUser();

	@DenyAll
	String jsr250();

	@PermitAll
	String jsr250PermitAll();

	@RolesAllowed("ADMIN")
	String jsr250RolesAllowed();

	@RolesAllowed("USER")
	String jsr250RolesAllowedUser();

	@Secured({ "ROLE_USER", "RUN_AS_SUPER" })
	Authentication runAs();

	@PreAuthorize("permitAll")
	String preAuthorizePermitAll();

	@PreAuthorize("!anonymous")
	void preAuthorizeNotAnonymous();

	@PreAuthorize("@authz.check(#result)")
	void preAuthorizeBean(@P("result") boolean result);

	@PreAuthorize("hasRole('ADMIN')")
	void preAuthorizeAdmin();

	@PreAuthorize("hasRole('USER')")
	void preAuthorizeUser();

	@PreAuthorize("hasPermission(#object,'read')")
	String hasPermission(String object);

	@PostAuthorize("hasPermission(#object,'read')")
	String postHasPermission(String object);

	@PostAuthorize("#o?.contains('grant')")
	String postAnnotation(@P("o") String object);

	@PreFilter("filterObject == authentication.name")
	List<String> preFilterByUsername(List<String> array);

	@PostFilter("filterObject == authentication.name")
	List<String> postFilterByUsername(List<String> array);

	@PreFilter("filterObject.length > 3")
	@PreAuthorize("hasRole('ADMIN')")
	@Secured("ROLE_USER")
	@PostFilter("filterObject.length > 5")
	@PostAuthorize("returnObject.size == 2")
	List<String> manyAnnotations(List<String> array);

	@PreFilter("filterObject != 'DropOnPreFilter'")
	@PreAuthorize("#list.remove('DropOnPreAuthorize')")
	@Secured("ROLE_SECURED")
	@RolesAllowed("JSR250")
	@PostAuthorize("#list.remove('DropOnPostAuthorize')")
	@PostFilter("filterObject != 'DropOnPostFilter'")
	List<String> allAnnotations(List<String> list);

	@RequireUserRole
	@RequireAdminRole
	void repeatedAnnotations();

	@org.springframework.security.authorization.method.PreAuthorize(value = "hasRole('ADMIN')",
			handlerClass = StarMaskingHandler.class)
	String preAuthorizeGetCardNumberIfAdmin(String cardNumber);

	@org.springframework.security.authorization.method.PreAuthorize(value = "hasRole('ADMIN')",
			handlerClass = StartMaskingHandlerChild.class)
	String preAuthorizeWithHandlerChildGetCardNumberIfAdmin(String cardNumber);

	@org.springframework.security.authorization.method.PreAuthorize(value = "hasRole('ADMIN')",
			handlerClass = StarMaskingHandler.class)
	String preAuthorizeThrowAccessDeniedManually();

	@org.springframework.security.authorization.method.PostAuthorize(value = "hasRole('ADMIN')",
			postProcessorClass = CardNumberMaskingPostProcessor.class)
	String postAuthorizeGetCardNumberIfAdmin(String cardNumber);

	@org.springframework.security.authorization.method.PostAuthorize(value = "hasRole('ADMIN')",
			postProcessorClass = PostMaskingPostProcessor.class)
	String postAuthorizeThrowAccessDeniedManually();

	@org.springframework.security.authorization.method.PreAuthorize(value = "denyAll()",
			handlerClass = MaskAnnotationHandler.class)
	@Mask("methodmask")
	String preAuthorizeDeniedMethodWithMaskAnnotation();

	@org.springframework.security.authorization.method.PreAuthorize(value = "denyAll()",
			handlerClass = MaskAnnotationHandler.class)
	String preAuthorizeDeniedMethodWithNoMaskAnnotation();

	@NullDenied(role = "ADMIN")
	String postAuthorizeDeniedWithNullDenied();

	@org.springframework.security.authorization.method.PostAuthorize(value = "denyAll()",
			postProcessorClass = MaskAnnotationPostProcessor.class)
	@Mask("methodmask")
	String postAuthorizeDeniedMethodWithMaskAnnotation();

	@org.springframework.security.authorization.method.PostAuthorize(value = "denyAll()",
			postProcessorClass = MaskAnnotationPostProcessor.class)
	String postAuthorizeDeniedMethodWithNoMaskAnnotation();

	@org.springframework.security.authorization.method.PreAuthorize(value = "hasRole('ADMIN')",
			handlerClass = MaskAnnotationHandler.class)
	@Mask(expression = "@myMasker.getMask()")
	String preAuthorizeWithMaskAnnotationUsingBean();

	@org.springframework.security.authorization.method.PostAuthorize(value = "hasRole('ADMIN')",
			postProcessorClass = MaskAnnotationPostProcessor.class)
	@Mask(expression = "@myMasker.getMask(returnObject)")
	String postAuthorizeWithMaskAnnotationUsingBean();

	@AuthorizeReturnObject
	UserRecordWithEmailProtected getUserRecordWithEmailProtected();

	@org.springframework.security.authorization.method.PreAuthorize(value = "hasRole('ADMIN')",
			handlerClass = UserFallbackDeniedHandler.class)
	UserRecordWithEmailProtected getUserWithFallbackWhenUnauthorized();

	class StarMaskingHandler implements MethodAuthorizationDeniedHandler {

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			return "***";
		}

	}

	class StartMaskingHandlerChild extends StarMaskingHandler {

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			return super.handle(methodInvocation, result) + "-child";
		}

	}

	class MaskAnnotationHandler implements MethodAuthorizationDeniedHandler {

		MaskValueResolver maskValueResolver;

		MaskAnnotationHandler(ApplicationContext context) {
			this.maskValueResolver = new MaskValueResolver(context);
		}

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			Mask mask = AnnotationUtils.getAnnotation(methodInvocation.getMethod(), Mask.class);
			if (mask == null) {
				mask = AnnotationUtils.getAnnotation(methodInvocation.getMethod().getDeclaringClass(), Mask.class);
			}
			return this.maskValueResolver.resolveValue(mask, methodInvocation, null);
		}

	}

	class MaskAnnotationPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		MaskValueResolver maskValueResolver;

		MaskAnnotationPostProcessor(ApplicationContext context) {
			this.maskValueResolver = new MaskValueResolver(context);
		}

		@Override
		public Object postProcessResult(MethodInvocationResult methodInvocationResult,
				AuthorizationResult authorizationResult) {
			MethodInvocation mi = methodInvocationResult.getMethodInvocation();
			Mask mask = AnnotationUtils.getAnnotation(mi.getMethod(), Mask.class);
			if (mask == null) {
				mask = AnnotationUtils.getAnnotation(mi.getMethod().getDeclaringClass(), Mask.class);
			}
			return this.maskValueResolver.resolveValue(mask, mi, methodInvocationResult.getResult());
		}

	}

	class MaskValueResolver {

		DefaultMethodSecurityExpressionHandler expressionHandler;

		MaskValueResolver(ApplicationContext context) {
			this.expressionHandler = new DefaultMethodSecurityExpressionHandler();
			this.expressionHandler.setApplicationContext(context);
		}

		String resolveValue(Mask mask, MethodInvocation mi, Object returnObject) {
			if (StringUtils.hasText(mask.value())) {
				return mask.value();
			}
			Expression expression = this.expressionHandler.getExpressionParser().parseExpression(mask.expression());
			EvaluationContext evaluationContext = this.expressionHandler
				.createEvaluationContext(() -> SecurityContextHolder.getContext().getAuthentication(), mi);
			if (returnObject != null) {
				this.expressionHandler.setReturnObject(returnObject, evaluationContext);
			}
			return expression.getValue(evaluationContext, String.class);
		}

	}

	class PostMaskingPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		@Override
		public Object postProcessResult(MethodInvocationResult contextObject, AuthorizationResult result) {
			return "***";
		}

	}

	class CardNumberMaskingPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		static String MASK = "****-****-****-";

		@Override
		public Object postProcessResult(MethodInvocationResult contextObject, AuthorizationResult result) {
			String cardNumber = (String) contextObject.getResult();
			return MASK + cardNumber.substring(cardNumber.length() - 4);
		}

	}

	class NullPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		@Override
		public Object postProcessResult(MethodInvocationResult methodInvocationResult,
				AuthorizationResult authorizationResult) {
			return null;
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@interface Mask {

		String value() default "";

		String expression() default "";

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@org.springframework.security.authorization.method.PostAuthorize(value = "hasRole('{value}')",
			postProcessorClass = NullPostProcessor.class)
	@interface NullDenied {

		String role();

	}

	class UserFallbackDeniedHandler implements MethodAuthorizationDeniedHandler {

		private static final UserRecordWithEmailProtected FALLBACK = new UserRecordWithEmailProtected("Protected",
				"Protected");

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
			return FALLBACK;
		}

	}

}
