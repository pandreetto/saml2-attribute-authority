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
     * SCIM section
     */

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException;

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException;

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException;

    /*
     * SAML2 section
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