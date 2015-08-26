package it.infn.security.saml.iam;

import it.infn.security.saml.iam.impl.XACMLAccessManager;

public class AccessManagerFactory {

    private static AccessManager manager = null;

    public static AccessManager getManager() {

        if (manager == null) {

            synchronized (AccessManagerFactory.class) {

                if (manager == null) {

                    manager = new XACMLAccessManager();

                }
            }
        }

        return manager;
    }
}