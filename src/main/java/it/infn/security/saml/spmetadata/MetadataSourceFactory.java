package it.infn.security.saml.spmetadata;

public class MetadataSourceFactory {

    private static MetadataSource mdSource = null;

    public static MetadataSource getMetadataSource()
        throws MetadataSourceException {

        if (mdSource == null) {

            synchronized (MetadataSourceFactory.class) {

                if (mdSource == null) {

                    try {

                        int maxPriority = -1;
                        for (MetadataSource tmpmds : MetadataSource.mdSourceLoader) {
                            if (tmpmds.getLoadPriority() > maxPriority) {
                                maxPriority = tmpmds.getLoadPriority();
                                mdSource = tmpmds;
                            }
                        }
                    } catch (Exception ex) {
                        throw new MetadataSourceException("Cannot load metadata source", ex);
                    }

                    if (mdSource == null) {
                        throw new MetadataSourceException("Cannot find data source");
                    }

                    mdSource.init();
                }
            }
        }

        return mdSource;
    }
}