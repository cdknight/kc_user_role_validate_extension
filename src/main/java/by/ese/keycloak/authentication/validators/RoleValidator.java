package by.ese.keycloak.authentication.validators;

import com.fasterxml.jackson.core.type.TypeReference;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.util.JsonSerialization;
import org.jboss.logging.Logger;

import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.TimeZone;
import java.util.Date;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.io.IOException;
import java.time.Instant;


public class RoleValidator implements Authenticator {
    public static final RoleValidator SINGLETON = new RoleValidator();
    private static final Logger logger = Logger.getLogger(RoleValidator.class);
    // From https://github.com/keycloak/keycloak/blob/main/server-spi/src/main/java/org/keycloak/models/IdentityProviderMapperModel.java#L38
    private static final TypeReference<List<StringPair>> MAP_TYPE_REPRESENTATION = new TypeReference<List<StringPair>>() {
    };

    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

	logger.warn(authConfig.getId());

        if (user != null && authConfig != null && authConfig.getConfig() != null) {
	    // VARIABLE SETUP
            String requiredRole = authConfig.getConfig().get(RoleValidatorFactory.UNIVERSAL_ROLE);
	    String configMap = authConfig.getConfig().get(RoleValidatorFactory.RBAC_SETTINGS);
	    String clientId = context.getAuthenticationSession().getClient().getClientId(); // We use this to validate the given roles

	    Map<String, String> rbacSettingsMap = null; // Map of clients to allowed roles for those clients

	    // From https://github.com/keycloak/keycloak/blob/main/server-spi/src/main/java/org/keycloak/models/IdentityProviderMapperModel.java#L96 
	    try {
 		    List<StringPair> map = JsonSerialization.readValue(configMap, MAP_TYPE_REPRESENTATION);
		    rbacSettingsMap = map.stream().collect(Collectors.toMap(StringPair::getKey, StringPair::getValue));
	    }
	    catch (IOException e) {
		    logger.error("Failed to parse RBAC mapping!");
		    return false;
	    } 
	    // Note that we do not return false for a null map since the user may still have the universal role.


	    // PASSWORD EXPIRY VALIDATION
	    
	    Optional<String> pwExpirationS = user.getAttributeStream("passwordExpiration").findFirst();
	    if (!pwExpirationS.isPresent()) {
                // The user does not have a password expiry
                logger.warn("User does not have a passwordExpiration attribute!!");
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

	    // ROLE VALIDATION

            RoleModel universalRole = KeycloakModelUtils.getRoleFromString(realm, requiredRole);
            if (universalRole == null) {
                logger.errorv("Invalid role name submitted: {0}", requiredRole);
                return false;
            }
	    // Check if the user has the universal role, since that overrides everything.
	    if (user.hasRole(universalRole)) {
		    logger.warn("NOTE: User has universal role. Granting access.");
		    return true;
	    }

	    if (rbacSettingsMap != null) {
		    String[] allowedRolesForClient = null;
		    String rbacValue = rbacSettingsMap.get(clientId);
		    if (rbacValue != null) {
			    allowedRolesForClient = rbacValue.split(";");
		    }
		    // No validation: if the array is empty then this loop will just not happen
		    for (String role: allowedRolesForClient) {
			    RoleModel clientRole = KeycloakModelUtils.getRoleFromString(realm, role);
			    if (clientRole == null) {
				logger.errorv("Invalid role name submitted: {0}", role);
				return false;
			    }
			    // Check if user has an allowed role for the given client
			    if (user.hasRole(clientRole)) {
				    logger.warn("NOTE: User has allowed role for this client. Granting access.");
				    return true;
			    }
		    }
	    }

	    logger.warn("Deny access, user does not have valid roles for this client.");
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
    // From https://github.com/keycloak/keycloak/blob/main/server-spi/src/main/java/org/keycloak/models/IdentityProviderMapperModel.java#L124
    static class StringPair {
        private String key;
        private String value;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
