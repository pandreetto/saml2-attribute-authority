package it.infn.security.saml.iam;

import org.opensaml.saml2.core.AttributeQuery;

public class AccessManagerFactory {

    private static AccessManager manager = null;

    public static synchronized AccessManager getManager() {

        if (manager == null) {
            manager = new AccessManager() {
                public void init() {
                }

                public void authorizeAttributeQuery(AttributeQuery query) {
                }

                public void close() {
                }
            };
        }
        return manager;
    }
}