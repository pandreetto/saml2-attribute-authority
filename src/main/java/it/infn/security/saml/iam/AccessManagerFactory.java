package it.infn.security.saml.iam;

public class AccessManagerFactory {

    private static AccessManager manager = null;

    public static AccessManager getManager()
        throws AccessManagerException {

        if (manager == null) {

            synchronized (AccessManagerFactory.class) {

                if (manager == null) {

                    int maxPriority = -1;
                    for (AccessManager tmpMan : AccessManager.accessManagerLoader) {
                        if (tmpMan.getLoadPriority() > maxPriority) {
                            maxPriority = tmpMan.getLoadPriority();
                            manager = tmpMan;
                        }
                    }

                    if (manager == null) {
                        throw new AccessManagerException("Cannot find access manager");
                    }
                    
                    manager.init();

                }
            }
        }

        return manager;
    }
}