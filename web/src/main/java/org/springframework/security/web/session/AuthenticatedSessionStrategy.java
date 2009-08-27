package org.springframework.security.web.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Allows pluggable support for Http session-related behaviour when an authentication occurs.
 * <p>
 * Typical use would be to make sure a session exists or to change the session Id to guard against session-fixation
 * attacks.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since
 */
public interface AuthenticatedSessionStrategy {

    /**
     * Performs Http session-related functionality when a new authentication occurs.
     *
     * @throws AuthenticationException if it is decided that the authentication is not allowed for the session.
     */
    void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException;

}
