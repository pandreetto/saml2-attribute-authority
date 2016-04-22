package it.infn.security.saml.ocp;

import it.infn.security.saml.spmetadata.MetadataSource;
import it.infn.security.saml.spmetadata.MetadataSourceException;
import it.infn.security.saml.spmetadata.SPMetadata;

public class AgIDMetadataSource
    implements MetadataSource {

    public void init()
        throws MetadataSourceException {

    }

    public SPMetadata getMetadata(String entityId)
        throws MetadataSourceException {
        return null;
    }

    public void close()
        throws MetadataSourceException {

    }

    public int getLoadPriority() {
        return 0;
    }

}