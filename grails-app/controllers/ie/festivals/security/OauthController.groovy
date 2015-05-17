/*
 * Copyright 2013-2015 Alvaro Sanchez-Mariscal <alvaro.sanchezmariscal@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package ie.festivals.security

import grails.plugins.springsecurity.Secured
import grails.plugins.springsecurity.SpringSecurityService
import ie.festivals.OauthService
import ie.festivals.User
import ie.festivals.UserRegistrationService
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.pac4j.core.client.RedirectAction
import org.pac4j.core.context.J2EContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.profile.CommonProfile
import org.pac4j.oauth.client.BaseOAuthClient

@Secured(['permitAll'])
class OauthController {

    static allowedMethods = [accessToken: 'POST']

    OauthService oauthService
    GrailsApplication grailsApplication
    SpringSecurityService springSecurityService
    UserRegistrationService userRegistrationService

    /**
     * Starts the OAuth authentication flow, redirecting to the provider's Login URL. An optional callback parameter
     * allows the frontend application to define the frontend callback URL on demand.
     */
    def authenticate(String provider) {
        BaseOAuthClient client = oauthService.getClient(provider)
        WebContext context = new J2EContext(request, response)

        RedirectAction redirectAction = client.getRedirectAction(context, true, false)
        log.debug "Redirecting to ${redirectAction.location}"
        redirect url: redirectAction.location
    }

    /**
     * Handles the OAuth provider callback.
     */
    def callback(String provider) {
        WebContext context = new J2EContext(request, response)

        try {
            CommonProfile profile = oauthService.getUserProfile(provider, context)

            User socialUserDetails = new User(
                    name: profile.displayName,
                    username: profile.email,
                    socialId: profile.username,
                    socialLoginProvider: provider
            )

            User registeredUser = userRegistrationService.socialSignIn(socialUserDetails)

            if (registeredUser.isTwitter() && !registeredUser.id) {
                // User is trying to register with Twitter, so they need to submit a form to
                // supply us with their email
                render view: '/register/confirmEmail', model: [user: registeredUser]
                return
            }
            springSecurityService.reauthenticate(registeredUser.username)
            flashHelper.info 'social.login.success': provider
            redirect uri: '/'

        } catch (ex) {
            log.error "Callback from OAuth2 sign-in failed", ex
            flashHelper.warn 'social.login.fail'
            redirect uri: '/'
        }
    }
}
