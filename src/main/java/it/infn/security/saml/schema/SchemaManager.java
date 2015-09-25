package it.infn.security.saml.schema;

import java.util.List;
import java.util.ServiceLoader;

import org.wso2.charon.core.schema.SCIMResourceSchema;

public interface SchemaManager {

    public void init()
        throws SchemaManagerException;

    public SCIMResourceSchema getGroupSchema();

    public SCIMResourceSchema getUserSchema();

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException;

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException;

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException;

    public void close()
        throws SchemaManagerException;

    public int getLoadPriority();

    public static ServiceLoader<SchemaManager> schemaManagerLoader = ServiceLoader.load(SchemaManager.class);

}