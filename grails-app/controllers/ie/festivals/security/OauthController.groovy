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
    def callback(String provider, String error) {
        WebContext context = new J2EContext(request, response)

        if (!error) {
            try {
                CommonProfile profile = oauthService.getUserProfile(provider, context)
                User registeredUser = userRegistrationService.socialSignIn(profile, provider)

                if (!registeredUser.isAttached()) {
                    // User is trying to register with an OAuth provider (e.g. Twitter, Yahoo), that doesn't provide their
                    // email address so they need to submit a form to supply us with their email
                    return render view: '/register/confirmEmail', model: [user: registeredUser]                    
                }
                springSecurityService.reauthenticate(registeredUser.username)
                flashHelper.info 'social.login.success': provider
                return redirect uri: '/'
                
            } catch (ex) {
                log.error "Error occurred during callback from OAuth2 provider '$provider'", ex
            }
        } else {
            // Most likely explanation is that the user denied access on the consent screen which is not really an error
            log.warn "Callback from OAuth2 provider '$provider' failed due to error: $error"
        }

        flashHelper.warn 'social.login.fail'
        redirect uri: '/'
    }
}
