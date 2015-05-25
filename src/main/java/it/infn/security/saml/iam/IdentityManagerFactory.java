package it.infn.security.saml.iam;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

public class IdentityManagerFactory {

    private static IdentityManager manager = null;

    public static synchronized IdentityManager getManager()
        throws IdentityManagerException {

        if (manager == null) {

            try {
                AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
                Class<?> cls = Class.forName(config.getIdentityManagerClass());
                manager = (IdentityManager) cls.newInstance();
            } catch (Throwable th) {
                throw new IdentityManagerException("Cannot load identity manager", th);
            }

            manager.init();

        }
        return manager;
    }
}