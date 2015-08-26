package it.infn.security.saml.configuration;

public class AuthorityConfigurationFactory {

    private static AuthorityConfiguration configuration = null;

    public static AuthorityConfiguration getConfiguration()
        throws ConfigurationException {

        if (configuration == null) {

            synchronized (AuthorityConfigurationFactory.class) {

                if (configuration == null) {

                    int maxPriority = -1;
                    for (AuthorityConfiguration tmpconf : AuthorityConfiguration.configurationLoader) {
                        if (tmpconf.getLoadPriority() > maxPriority) {
                            maxPriority = tmpconf.getLoadPriority();
                            configuration = tmpconf;
                        }
                    }

                    if (configuration == null) {
                        throw new ConfigurationException("Cannot find configuration handler");
                    }
                }

            }

        }

        return configuration;
    }

}