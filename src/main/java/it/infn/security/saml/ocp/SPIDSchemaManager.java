package it.infn.security.saml.ocp;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.utils.SAML2ObjectBuilder;
import it.infn.security.scim.core.AttributeFilter;
import it.infn.security.scim.core.SCIM2Decoder;
import it.infn.security.scim.core.SCIMCoreConstants;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
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

    public static final String SPID_SCHEMA = "urn:it:infn:security:spid:attributes:1.0";

    public static final String SPID_ATTR_ID = "spidattributes";

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
     * *************************************************************************************************************
     * SCIM section
     * *************************************************************************************************************
     */

    public String getSCIMSchema() {
        return SPID_SCHEMA;
    }

    public String encode(AttributeEntry attribute)
        throws SchemaManagerException {

        try {

            StringWriter result = new StringWriter();
            JsonGenerator jGenerator = Json.createGenerator(result);

            jGenerator.writeStartObject();

            jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
            jGenerator.write(SPID_SCHEMA);
            jGenerator.writeEnd();

            jGenerator.write(NAME_ATTR_ID, attribute.getName().getNameId());
            jGenerator.write(NAME_FORMAT_ID, attribute.getName().getNameFormat());
            if (attribute.getName().getFriendlyName() != null)
                jGenerator.write(NAME_FRIEND_ID, attribute.getName().getFriendlyName());

            jGenerator.writeStartArray(VALUES_ATTR_ID);
            for (AttributeValueInterface attrValue : attribute) {

                String strValue = null;
                String objType = attrValue.getType();
                if (objType.equals(SPIDAttributeValue.SPID_STRING_TYPE)) {
                    strValue = (String) attrValue.getValue();
                } else if (objType.equals(SPIDAttributeValue.SPID_DATE_TYPE)) {
                    /*
                     * TODO verify encoding
                     */
                    strValue = Long.toString(((Date) attrValue.getValue()).getTime());
                }

                jGenerator.writeStartObject();
                jGenerator.write(VALUE_ATTR_ID, strValue);
                jGenerator.write(VALUE_TYPE_ID, objType);
                jGenerator.write(DESCR_ATTR_ID, attrValue.getDescription());
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

    public String encode(List<AttributeNameInterface> names)
        throws SchemaManagerException {

        try {
            StringWriter result = new StringWriter();
            JsonGenerator jGenerator = Json.createGenerator(result);

            jGenerator.writeStartObject();

            jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
            jGenerator.write(SPID_SCHEMA);
            jGenerator.writeEnd();

            jGenerator.writeStartArray(NAMES_ATTR_ID);
            for (AttributeNameInterface name : names) {
                jGenerator.writeStartObject();
                jGenerator.write(NAME_ATTR_ID, name.getNameId());
                jGenerator.write(NAME_FORMAT_ID, name.getNameFormat());
                if (name.getFriendlyName() != null)
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

    public void encode(Collection<AttributeEntry> extAttrs, JsonGenerator jGenerator, AttributeFilter attrFilter)
        throws SchemaManagerException {

        if (extAttrs == null || extAttrs.size() == 0)
            return;

        if (!attrFilter.canShowNS(SPID_SCHEMA, SPID_ATTR_ID))
            return;

        jGenerator.writeStartObject(SPID_SCHEMA);
        jGenerator.writeStartArray(SPID_ATTR_ID);
        for (AttributeEntry attr : extAttrs) {
            for (AttributeValueInterface attrVal : attr) {
                jGenerator.writeStartObject();
                jGenerator.write(SPIDSchemaManager.NAME_ATTR_ID, attr.getName().getNameId());
                jGenerator.write(SPIDSchemaManager.VALUE_ATTR_ID, attrVal.getValue().toString());
                jGenerator.writeEnd();
            }
        }
        jGenerator.writeEnd().writeEnd();

    }

    private boolean checkSchema(JsonParser jParser)
        throws SchemaManagerException {

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {
            if (evn == JsonParser.Event.VALUE_STRING) {
                if (SPID_SCHEMA.equals(jParser.getString()))
                    return true;
            } else {
                throw new JsonParsingException("Bad schema definition", jParser.getLocation());
            }
        }

        return false;

    }

    private void checkValues(JsonParser jParser, HashSet<SPIDAttributeValue> valueTable)
        throws SchemaManagerException {

        String keyName = null;
        String currValue = null;
        String currType = null;
        String currDescr = null;

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {

            if (evn == JsonParser.Event.KEY_NAME) {
                keyName = jParser.getString().toLowerCase();
            } else if (evn == JsonParser.Event.VALUE_STRING) {

                if (VALUE_ATTR_ID.equals(keyName))
                    currValue = jParser.getString();
                else if (VALUE_TYPE_ID.equals(keyName))
                    currType = jParser.getString();
                else if (DESCR_ATTR_ID.equals(keyName))
                    currDescr = jParser.getString();

            } else if (evn == JsonParser.Event.START_OBJECT) {

                currValue = null;
                currType = null;
                currDescr = null;

            } else if (evn == JsonParser.Event.END_OBJECT) {

                if (currValue == null)
                    throw new SchemaManagerException("Missing attribute value");
                valueTable.add(new SPIDAttributeValue(currValue, currType, currDescr));

            } else {
                throw new JsonParsingException("Unrecognized schema", jParser.getLocation());
            }
        }
    }

    public AttributeEntry parse(String data)
        throws SchemaManagerException {

        try {

            String attrName = null;
            String friendName = null;
            HashSet<SPIDAttributeValue> valueTable = new HashSet<SPIDAttributeValue>();

            JsonParser jParser = Json.createParser(new StringReader(data));

            String keyName = null;
            boolean init = false;
            boolean foundSchema = false;

            while (jParser.hasNext()) {
                JsonParser.Event evn = jParser.next();

                if (evn == JsonParser.Event.KEY_NAME) {

                    keyName = jParser.getString().toLowerCase();

                } else if (evn == JsonParser.Event.VALUE_STRING) {

                    if (NAME_ATTR_ID.equals(keyName))
                        attrName = jParser.getString();
                    else if (NAME_FRIEND_ID.equals(keyName))
                        friendName = jParser.getString();

                } else if (evn == JsonParser.Event.START_OBJECT) {

                    if (init)
                        throw new JsonParsingException("Unrecognized object", jParser.getLocation());
                    init = true;

                } else if (evn == JsonParser.Event.START_ARRAY) {

                    if (VALUES_ATTR_ID.equals(keyName)) {
                        checkValues(jParser, valueTable);
                    } else if (SCIMCoreConstants.SCHEMAS.equals(keyName)) {
                        foundSchema = checkSchema(jParser);
                    } else {
                        throw new JsonParsingException("Unrecognized array " + keyName, jParser.getLocation());
                    }
                }
            }

            if (!foundSchema)
                throw new SchemaManagerException("Missing SPID schema");
            if (attrName == null)
                throw new SchemaManagerException("Missing attribute name");
            if (valueTable.size() == 0)
                throw new SchemaManagerException("No values specified " + attrName);

            AttributeEntry result = new AttributeEntry(new SPIDAttributeName(attrName, friendName));
            result.addAll(valueTable);
            return result;

        } catch (SchemaManagerException sEx) {
            throw sEx;
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException(ex.getMessage());
        }
    }

    public Collection<AttributeEntry> parse(JsonParser jParser)
        throws SchemaManagerException {

        String kName = null;
        String attrName = null;
        String attrValue = null;
        boolean inObj = false;
        HashMap<String, AttributeEntry> extMap = new HashMap<String, AttributeEntry>();
        boolean init = false;

        JsonParser.Event evn = jParser.next();
        if (evn != JsonParser.Event.START_OBJECT) {
            throw new SchemaManagerException("Missing SPID namespace");
        }

        evn = jParser.next();
        if (evn != JsonParser.Event.KEY_NAME && !SCIM2Decoder.getKeyName(jParser).equals(SPID_ATTR_ID)) {
            throw new SchemaManagerException("Undefined attribute " + SPID_ATTR_ID);
        }

        for (evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {

            if (evn == JsonParser.Event.START_OBJECT) {

                attrName = null;
                attrValue = null;
                inObj = true;

            } else if (evn == JsonParser.Event.END_OBJECT) {

                if (attrName == null)
                    throw new JsonParsingException("Missing attribute name", jParser.getLocation());
                if (attrValue == null)
                    throw new JsonParsingException("Missing attribute value", jParser.getLocation());
                if (!extMap.containsKey(attrName)) {
                    extMap.put(attrName, new AttributeEntry(new SPIDAttributeName(attrName, null)));
                }
                extMap.get(attrName).add(new SPIDAttributeValue(attrValue, ""));
                inObj = false;

            } else if (evn == JsonParser.Event.KEY_NAME) {

                if (!inObj)
                    throw new JsonParsingException("Unrelated property", jParser.getLocation());
                kName = SCIM2Decoder.getKeyName(jParser);

            } else if (evn == JsonParser.Event.VALUE_STRING) {

                if (SPIDSchemaManager.NAME_ATTR_ID.equals(kName)) {
                    attrName = jParser.getString();
                } else if (SPIDSchemaManager.VALUE_ATTR_ID.equals(kName)) {
                    attrValue = jParser.getString();
                }

                kName = null;

            } else if (evn == JsonParser.Event.START_ARRAY) {

                if (init)
                    throw new SchemaManagerException("Illegal nested array");
                init = true;

            } else {
                throw new SchemaManagerException("Wrong SPID definitions");
            }
        }

        evn = jParser.next();
        if (evn != JsonParser.Event.END_OBJECT) {
            throw new SchemaManagerException("SPID namespace is not closed");
        }

        return extMap.values();
    }

    /*
     * *************************************************************************************************************
     * SAML2 section
     * *************************************************************************************************************
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