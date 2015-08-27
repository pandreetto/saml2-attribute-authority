package it.infn.security.saml.schema;

import java.util.ServiceLoader;

import org.wso2.charon.core.schema.SCIMResourceSchema;

public interface SchemaManager {

    public void init()
        throws SchemaManagerException;

    public SCIMResourceSchema getGroupSchema();

    public SCIMResourceSchema getUserSchema();

    public void close()
        throws SchemaManagerException;

    public int getLoadPriority();

    public static ServiceLoader<SchemaManager> schemaManagerLoader = ServiceLoader.load(SchemaManager.class);

}