package by.ese.keycloak.authentication.validators;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.jboss.logging.Logger;

import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.TimeZone;
import java.util.Date;
import java.util.Optional;
import java.time.Instant;

public class RoleValidator implements Authenticator {
    public static final RoleValidator SINGLETON = new RoleValidator();
    private static final Logger logger = Logger.getLogger(RoleValidator.class);

    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

        if (user != null && authConfig!=null && authConfig.getConfig()!=null) {
            String requiredRole = authConfig.getConfig().get(RoleValidatorFactory.USER_ROLE);
            RoleModel role = KeycloakModelUtils.getRoleFromString(realm, requiredRole);
            if (role == null) {
                logger.errorv("Invalid role name submitted: {0}", requiredRole);
                return false;
            }
	    // Perform user password expiry validation
	    Optional<String> pwExpirationS = user.getAttributeStream("passwordExpiration").findFirst();
	    if (!pwExpirationS.isPresent()) {
		// The user does not have a password expiry
		logger.warn("User does not have a passwordExpiration attribute!!");
		// Return false
		return false;
			
	    }
	    // Yes, I know I shouldn't use java.util.Date. But... this is simpler.
	    SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
	    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));

	    Date userPwExpirationTime = null;
	    try {
		    userPwExpirationTime = formatter.parse(pwExpirationS.get());
	    }
            catch (ParseException pExc) {
		    logger.warn("Failed to parse use password expiration time!!");
		    return false;
	    }
	    // Check if password is expired
	    // TODO will userPwExpiriationTime ever be null?
	    if (userPwExpirationTime != null) {
		    if (Date.from(Instant.now()).after(userPwExpirationTime)) {
			    logger.warn("User password has expired, refuse login.");
			    return false;
		    }
	    }
	    
	    // NOW check if the user has the role.
	    if (user.hasRole(role)) {
		    logger.warn("NOTE: User has role. Granting access.");
		    return true;
	    }
	    logger.warn("Deny access, user does not have valid roles.");
        }
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        if(matchCondition(authenticationFlowContext)) {
            authenticationFlowContext.success();
        } else {
            authenticationFlowContext.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
