package by.ese.keycloak.authentication.validators;

import org.keycloak.Config.Scope;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.DisplayTypeAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Collections;
import java.util.List;

public class RoleValidatorFactory implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {
    public static final String PROVIDER_ID = "user-role-validator";
    protected static final String UNIVERSAL_ROLE = "validatedUniversalRole";
    protected static final String RBAC_SETTINGS = "validatedRBAC";

    private static final List<ProviderConfigProperty> commonConfig;

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
            .property().name(UNIVERSAL_ROLE).label("Universal role")
            .helpText("Role that if, is present, will allow universal access to all clients. Click 'Select Role' button to browse roles")
            .type(ProviderConfigProperty.ROLE_TYPE).add()

            .property().name(RBAC_SETTINGS).label("RBAC settings")
            .helpText("Configure RBAC mappings, allowing only certain clients to certain roles." + 
		    "The keys are the names of client_ids that you want to filder and the values" + 
		    " are a semicolon-separated list of roles that should be allowed for said client." + 
		    "Example key: \"client\" and value: \"trusted-users;people;world\""
		    )
            .type(ProviderConfigProperty.MAP_TYPE).add()

            .build()
        );
    }

    @Override
    public void init(Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Validate User Role";
    }

    @Override
    public String getReferenceCategory() {
        return "Role validation";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED

    };

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if the user has the given role.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    public RoleValidator getSingleton() {
        return RoleValidator.SINGLETON;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return getSingleton();
    }

    @Override
    public Authenticator createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return getSingleton();
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return getSingleton();
    }
}
