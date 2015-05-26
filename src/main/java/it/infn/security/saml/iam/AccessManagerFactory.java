package it.infn.security.saml.iam;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.AttributeQuery;

public class AccessManagerFactory {

    private static AccessManager manager = null;

    public static synchronized AccessManager getManager() {

        if (manager == null) {
            manager = new AccessManager() {
                public void init() {
                }

                public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query) {
                    return new AccessConstraints();
                }

                public void close() {
                }
            };
        }
        return manager;
    }
}