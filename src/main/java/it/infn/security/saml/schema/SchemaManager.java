package it.infn.security.saml.schema;

import java.util.List;
import java.util.ServiceLoader;

import org.opensaml.saml2.core.AttributeQuery;
import org.wso2.charon.core.schema.SCIMResourceSchema;

public interface SchemaManager {

    public void init()
        throws SchemaManagerException;

    /*
     * SCIM section
     */

    public SCIMResourceSchema getGroupSchema();

    public SCIMResourceSchema getUserSchema();

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException;

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException;

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException;

    /*
     * SAML2 section
     */

    public String[] getSupportedProtocols();

    public String[] getSupportedAttributeProfiles();

    public String[] getSupportedNameIDFormats();

    public void checkRequest(AttributeQuery query)
        throws SchemaManagerException;

    public String getResponseDestination();

    public boolean requiredSignedAssertion();

    public boolean requiredSignedResponse();

    public boolean requiredSignedQuery();

    public String generateAssertionID();

    public String generateResponseID();

    public void close()
        throws SchemaManagerException;

    public int getLoadPriority();

    public static ServiceLoader<SchemaManager> schemaManagerLoader = ServiceLoader.load(SchemaManager.class);

}