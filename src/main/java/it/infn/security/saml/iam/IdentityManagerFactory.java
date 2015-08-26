package it.infn.security.saml.iam;

public class IdentityManagerFactory {

    private static IdentityManager manager = null;

    public static IdentityManager getManager()
        throws IdentityManagerException {

        if (manager == null) {

            synchronized (IdentityManagerFactory.class) {

                if (manager == null) {

                    int maxPriority = -1;
                    for (IdentityManager tmpMan : IdentityManager.identManagerLoader) {
                        if (tmpMan.getLoadPriority() > maxPriority) {
                            maxPriority = tmpMan.getLoadPriority();
                            manager = tmpMan;
                        }
                    }

                    if (manager == null) {
                        throw new IdentityManagerException("Cannot find identity manager");
                    }

                    manager.init();

                }

            }

        }
        return manager;
    }
}