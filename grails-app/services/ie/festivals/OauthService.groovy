package ie.festivals

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import org.pac4j.core.context.WebContext
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.profile.CommonProfile
import org.pac4j.oauth.client.BaseOAuthClient

/**
 * Deals with pac4j library to fetch a user profile from the selected OAuth provider, and stores it on the security context
 */
class OauthService {

    static transactional = false

    GrailsApplication grailsApplication
    LinkGenerator grailsLinkGenerator

    BaseOAuthClient getClient(String provider) {
        log.debug "Creating OAuth client for provider: ${provider}"
        def providerConfig = grailsApplication.config.oauth."${provider}"
        def ClientClass = providerConfig.client

        BaseOAuthClient client
        if (ClientClass?.toString()?.endsWith("CasOAuthWrapperClient")) {
            client = ClientClass.newInstance(providerConfig.key, providerConfig.secret, providerConfig.casOAuthUrl)
        } else {
            client = ClientClass.newInstance(providerConfig.key, providerConfig.secret)
        }

        String callbackUrl = grailsLinkGenerator.link controller: 'oauth', action: 'callback', params: [provider: provider], absolute: true
        log.debug "Callback URL is: ${callbackUrl}"
        client.callbackUrl = callbackUrl

        if (providerConfig.scope) {
            client.scope = providerConfig.scope
        }

        if (providerConfig.fields) {
            client.fields = providerConfig.fields
        }

        return client
    }

    CommonProfile getUserProfile(String provider, WebContext context) {
        BaseOAuthClient client = getClient(provider)
        Credentials credentials = client.getCredentials context

        log.debug "Querying provider to fetch User ID"
        client.getUserProfile credentials, null
    }
}
