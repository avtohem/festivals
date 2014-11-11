package ie.festivals

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class LogoutController {

	/**
	 * Redirects to the Spring security logout uri.
	 */
	def index() {
		// put any pre-logout code here
		redirect uri: SpringSecurityUtils.securityConfig.logout.filterProcessesUrl // '/j_spring_security_logout'
	}
}