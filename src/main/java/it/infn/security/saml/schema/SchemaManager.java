package it.infn.security.saml.schema;

import java.util.List;
import java.util.ServiceLoader;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Audience;

public interface SchemaManager {

    public void init()
        throws SchemaManagerException;

    /*
     * *************************************************************************************************************
     * SCIM section
     * *************************************************************************************************************
     */

    public String getSCIMSchema();

    public String encode(AttributeEntry attribute)
        throws SchemaManagerException;

    public String encode(List<AttributeNameInterface> names)
        throws SchemaManagerException;

    public AttributeEntry parse(String data)
        throws SchemaManagerException;

    /*
     * *************************************************************************************************************
     * SAML2 section
     * *************************************************************************************************************
     */

    public String getAuthorityIDFormat();

    public String[] getSupportedProtocols();

    public String[] getSupportedAttributeProfiles();

    public String[] getSupportedNameIDFormats();

    public void checkRequest(AttributeQuery query, Subject requester)
        throws SchemaManagerException;

    public boolean assertionExpires();

    public List<Audience> getAudienceList(AttributeQuery query, Subject requester)
        throws SchemaManagerException;

    public String getResponseDestination(AttributeQuery query, Subject requester)
        throws SchemaManagerException;

    public Advice getAdvice(AttributeQuery query, Subject requester)
        throws SchemaManagerException;

    public boolean requiredSignedAssertion();

    public boolean requiredSignedResponse();

    public boolean requiredSignedQuery();

    public void checkSignatureAlgorithm(String algorithm)
        throws SchemaManagerException;

    public void checkDigestAlgorithm(String algorithm)
        throws SchemaManagerException;

    public String generateAssertionID();

    public String generateResponseID();

    public void close()
        throws SchemaManagerException;

    public int getLoadPriority();

    public static ServiceLoader<SchemaManager> schemaManagerLoader = ServiceLoader.load(SchemaManager.class);

}