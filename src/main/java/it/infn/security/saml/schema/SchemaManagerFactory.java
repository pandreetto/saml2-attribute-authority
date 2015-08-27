package it.infn.security.saml.schema;

public class SchemaManagerFactory {

    private static SchemaManager manager = null;

    public static SchemaManager getManager()
        throws SchemaManagerException {

        if (manager == null) {

            synchronized (SchemaManagerFactory.class) {

                if (manager == null) {

                    int maxPriority = -1;
                    for (SchemaManager tmpMan : SchemaManager.schemaManagerLoader) {
                        if (tmpMan.getLoadPriority() > maxPriority) {
                            maxPriority = tmpMan.getLoadPriority();
                            manager = tmpMan;
                        }
                    }

                    if (manager == null) {
                        throw new SchemaManagerException("Cannot find schema manager");
                    }

                    manager.init();
                }
            }
        }

        return manager;
    }
}