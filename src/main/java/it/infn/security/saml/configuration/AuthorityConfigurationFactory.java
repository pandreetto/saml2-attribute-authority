package it.infn.security.saml.configuration;

public class AuthorityConfigurationFactory {

    private static AuthorityConfiguration configuration = null;

    public static synchronized AuthorityConfiguration getConfiguration() {

        if (configuration == null) {
            configuration = new it.infn.security.saml.configuration.impl.PropertyFileConfiguration();
        }

        return configuration;
    }

}