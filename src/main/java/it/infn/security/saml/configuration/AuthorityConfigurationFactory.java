package it.infn.security.saml.configuration;

public class AuthorityConfigurationFactory {

    private static AuthorityConfiguration configuration = null;

    public static AuthorityConfiguration getConfiguration() {

        if (configuration == null) {

            synchronized (AuthorityConfigurationFactory.class) {

                if (configuration == null) {
                    configuration = new it.infn.security.saml.configuration.impl.PropertyFileConfiguration();
                }

            }

        }

        return configuration;
    }

}