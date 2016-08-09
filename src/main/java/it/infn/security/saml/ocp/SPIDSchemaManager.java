package it.infn.security.saml.ocp;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.utils.SAML2ObjectBuilder;
import it.infn.security.scim.core.SCIMCoreConstants;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.stream.JsonGenerator;
import javax.json.stream.JsonParser;
import javax.json.stream.JsonParsingException;
import javax.security.auth.Subject;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.Issuer;

public class SPIDSchemaManager
    implements SchemaManager {

    private static final Logger logger = Logger.getLogger(SPIDSchemaManager.class.getName());

    public static final String SPID_ATTR_URI = "urn:it:infn:security:spid:attributes:1.0";

    public static final String SPID_SCHEMA_URI = "urn:it:infn:security:spid:attributes:1.0";

    public static final String NAME_ATTR_ID = "name";

    public static final String NAME_FORMAT_ID = "format";

    public static final String NAME_FRIEND_ID = "friendlyname";

    public static final String VALUE_ATTR_ID = "value";

    public static final String VALUE_TYPE_ID = "type";

    public static final String DESCR_ATTR_ID = "description";

    public static final String VALUES_ATTR_ID = "values";

    public static final String NAMES_ATTR_ID = "names";

    public void init()
        throws SchemaManagerException {
    }

    /*
     * SCIM section
     */

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException {

        try {

            StringWriter result = new StringWriter();
            JsonGenerator jGenerator = Json.createGenerator(result);

            jGenerator.writeStartObject();

            jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
            jGenerator.write(SCIMCoreConstants.SPID_SCHEMA);
            jGenerator.writeEnd();

            jGenerator.write(NAME_ATTR_ID, attribute.getName().getNameId());
            jGenerator.write(NAME_FORMAT_ID, attribute.getName().getNameFormat());
            jGenerator.write(NAME_FRIEND_ID, attribute.getName().getFriendlyName());

            jGenerator.writeStartArray(VALUES_ATTR_ID);
            for (AttributeValueInterface value : attribute) {
                jGenerator.writeStartObject();
                jGenerator.write(VALUE_ATTR_ID, value.encode(format));
                jGenerator.write(VALUE_TYPE_ID, value.getType());
                jGenerator.write(DESCR_ATTR_ID, value.getDescription());
                jGenerator.writeEnd();
            }
            jGenerator.writeEnd();

            jGenerator.writeEnd().close();

            return result.toString();

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException("Cannot encode attribute");
        }
    }

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException {

        try {
            StringWriter result = new StringWriter();
            JsonGenerator jGenerator = Json.createGenerator(result);

            jGenerator.writeStartObject();

            jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
            jGenerator.write(SCIMCoreConstants.SPID_SCHEMA);
            jGenerator.writeEnd();

            jGenerator.writeStartArray(NAMES_ATTR_ID);
            for (AttributeNameInterface name : names) {
                jGenerator.writeStartObject();
                jGenerator.write(NAME_ATTR_ID, name.getNameId());
                jGenerator.write(NAME_FORMAT_ID, name.getNameFormat());
                jGenerator.write(NAME_FRIEND_ID, name.getFriendlyName());
                jGenerator.writeEnd();
            }
            jGenerator.writeEnd();

            jGenerator.writeEnd().close();

            return result.toString();

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException("Cannot encode attribute");
        }

    }

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException {

        try {

            AttributeEntry result = null;

            JsonParser jParser = Json.createParser(new StringReader(data));

            String keyName = null;
            boolean foundArray = false;
            String attrName = null;
            String friendName = null;
            String value = null;
            String type = null;
            String descr = null;

            while (jParser.hasNext()) {
                JsonParser.Event evn = jParser.next();

                if (evn == JsonParser.Event.KEY_NAME) {

                    keyName = jParser.getString().toLowerCase();

                } else if (evn == JsonParser.Event.VALUE_STRING) {

                    if (NAME_ATTR_ID.equals(keyName) && !foundArray)
                        attrName = jParser.getString();
                    else if (NAME_FRIEND_ID.equals(keyName) && !foundArray)
                        friendName = jParser.getString();
                    else if (VALUE_ATTR_ID.equals(keyName) && foundArray)
                        value = jParser.getString();
                    else if (VALUE_TYPE_ID.equals(keyName) && foundArray)
                        type = jParser.getString();
                    else if (DESCR_ATTR_ID.equals(keyName) && foundArray)
                        descr = jParser.getString();

                } else if (evn == JsonParser.Event.START_OBJECT) {

                    value = null;
                    type = null;
                    descr = null;

                } else if (evn == JsonParser.Event.END_OBJECT) {

                    if (foundArray) {
                        if (value == null)
                            throw new JsonParsingException("Missing " + VALUE_ATTR_ID, jParser.getLocation());
                        if (type == null)
                            throw new JsonParsingException("Missing " + VALUE_TYPE_ID, jParser.getLocation());
                        result.add(new SPIDAttributeValue(value, type, descr));
                    } else {
                        if (attrName == null)
                            throw new JsonParsingException("Missing " + NAME_ATTR_ID, jParser.getLocation());
                        result = new AttributeEntry(new SPIDAttributeName(attrName, friendName));
                    }

                } else if (evn == JsonParser.Event.START_ARRAY) {
                    if (foundArray)
                        throw new JsonParsingException("Illegal nested arrays", jParser.getLocation());
                    if (!VALUES_ATTR_ID.equals(keyName))
                        throw new JsonParsingException("Illegal array name " + keyName, jParser.getLocation());
                    foundArray = true;
                } else if (evn == JsonParser.Event.END_ARRAY) {
                    foundArray = false;
                }
            }

            return result;

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException(ex.getMessage());
        }
    }

    /*
     * SAML2 section
     */

    public String getAuthorityIDFormat() {
        return "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    }

    public String[] getSupportedProtocols() {
        return new String[] { "urn:oasis:names:tc:SAML:2.0:protocol" };
    }

    public String[] getSupportedAttributeProfiles() {
        return new String[] { "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" };
    }

    public String[] getSupportedNameIDFormats() {
        return new String[] { "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" };
    }

    public void checkRequest(AttributeQuery query, Subject requester)
        throws SchemaManagerException {

        Issuer issuer = query.getIssuer();
        if (issuer == null) {
            throw new SchemaManagerException("Issuer in request is mandatory");
        }
        /*
         * TODO check if the issuer of the query is a SPID-registered SP (retrieve metadata via AGID registry)
         */

        String queryDest = query.getDestination();
        if (queryDest == null || queryDest.length() == 0) {
            throw new SchemaManagerException("Destination in request is mandatory");
        }

        try {
            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

            if (!queryDest.equals(configuration.getAuthorityURL() + "/query")) {
                throw new SchemaManagerException("Destination mismatch");
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException("Cannot retrieve Attribute Service URL");
        }
    }

    public boolean assertionExpires() {
        return true;
    }

    public List<Audience> getAudienceList(AttributeQuery query, Subject requester)
        throws SchemaManagerException {

        ArrayList<Audience> result = new ArrayList<Audience>();
        Audience audience = SAML2ObjectBuilder.buildAudience();
        audience.setAudienceURI(query.getIssuer().getValue());
        result.add(audience);
        return result;

    }

    public String getResponseDestination(AttributeQuery query, Subject requester)
        throws SchemaManagerException {
        /*
         * TODO return Attribute Service of the SP ??
         */
        return null;
    }

    public Advice getAdvice(AttributeQuery query, Subject requester)
        throws SchemaManagerException {
        return null;
    }

    public boolean requiredSignedAssertion() {
        return true;
    }

    public boolean requiredSignedResponse() {
        return false;
    }

    public boolean requiredSignedQuery() {
        return true;
    }

    public void checkSignatureAlgorithm(String algorithm)
        throws SchemaManagerException {

        if (!XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256.equals(algorithm)
                && !XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384.equals(algorithm)
                && !XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512.equals(algorithm)) {
            throw new SchemaManagerException("Signature algorithm not supported: " + algorithm);
        }
    }

    public void checkDigestAlgorithm(String algorithm)
        throws SchemaManagerException {
        if (!MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256.equals(algorithm)
                && !MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384.equals(algorithm)
                && !MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512.equals(algorithm)) {
            throw new SchemaManagerException("Digest algorithm not supported: " + algorithm);
        }
    }

    public String generateAssertionID() {
        return "_" + UUID.randomUUID().toString();
    }

    public String generateResponseID() {
        return "_" + UUID.randomUUID().toString();
    }

    public void close()
        throws SchemaManagerException {

    }

    public int getLoadPriority() {
        return 0;
    }

}