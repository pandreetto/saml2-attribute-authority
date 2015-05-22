package it.infn.security.saml.iam;

public class IdentityManagerFactory {

    private static IdentityManager manager = null;

    public static synchronized IdentityManager getManager() {

        if (manager == null) {
            manager = new IdentityManager() {
                public void init() {
                }

                public void authenticate() {
                }

                public void close() {
                }
            };
        }
        return manager;
    }
}