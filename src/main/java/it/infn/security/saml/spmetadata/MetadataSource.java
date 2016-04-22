package it.infn.security.saml.spmetadata;

import java.util.ServiceLoader;

public interface MetadataSource {

    public void init()
        throws MetadataSourceException;

    public SPMetadata getMetadata(String entityId)
        throws MetadataSourceException;

    public void close()
        throws MetadataSourceException;

    public int getLoadPriority();

    public static ServiceLoader<MetadataSource> mdSourceLoader = ServiceLoader.load(MetadataSource.class);

}