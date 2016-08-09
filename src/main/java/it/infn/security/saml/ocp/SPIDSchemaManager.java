package it.infn.security.saml.ocp;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.utils.SAML2ObjectBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
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

    public static final String ROOT_ATTR_ID = "SPIDAttributes";

    public void init()
        throws SchemaManagerException {
    }

    /*
     * SCIM section
     */

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException {

        try {

            JSONObject rootObject = new JSONObject();
            rootObject.put("schemas", SPID_SCHEMA_URI);
            rootObject.put(NAME_ATTR_ID, attribute.getName().getNameId());
            rootObject.put(NAME_FORMAT_ID, attribute.getName().getNameFormat());
            rootObject.put(NAME_FRIEND_ID, attribute.getName().getFriendlyName());

            JSONArray arrayObject = new JSONArray();
            for (AttributeValueInterface value : attribute) {
                JSONObject attrObject = new JSONObject();
                attrObject.put(VALUE_ATTR_ID, value.encode(format));
                attrObject.put(VALUE_TYPE_ID, value.getType());
                attrObject.put(DESCR_ATTR_ID, value.getDescription());
                arrayObject.put(attrObject);
            }
            rootObject.put(VALUES_ATTR_ID, arrayObject);

            return rootObject.toString();

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException("Cannot encode attribute");
        }
    }

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException {

        JSONObject rootObject = new JSONObject();
        try {
            rootObject.put("schemas", SPID_SCHEMA_URI);
            JSONArray arrayObject = new JSONArray();
            for (AttributeNameInterface name : names) {
                JSONObject nameObj = new JSONObject();
                nameObj.put(NAME_ATTR_ID, name.getNameId());
                nameObj.put(NAME_FORMAT_ID, name.getNameFormat());
                nameObj.put(NAME_FRIEND_ID, name.getFriendlyName());
                arrayObject.put(nameObj);
            }
            rootObject.put(NAMES_ATTR_ID, arrayObject);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new SchemaManagerException("Cannot encode attribute");
        }

        return rootObject.toString();
    }

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException {

        try {

            JSONObject jsonObj = new JSONObject(new JSONTokener(data));
            String nameId = jsonObj.optString(NAME_ATTR_ID);
            if (nameId == null)
                throw new SchemaManagerException("Missing " + NAME_ATTR_ID);
            String fName = jsonObj.optString(NAME_FRIEND_ID);

            AttributeEntry result = new AttributeEntry(new SPIDAttributeName(nameId, fName));

            JSONArray values = jsonObj.optJSONArray(VALUES_ATTR_ID);
            for (int k = 0; k < values.length(); k++) {
                JSONObject vObj = values.getJSONObject(k);
                String value = vObj.optString(VALUE_ATTR_ID);
                if (value == null)
                    throw new SchemaManagerException("Missing " + VALUE_ATTR_ID);
                String vType = vObj.optString(VALUE_TYPE_ID);
                if (vType == null)
                    throw new SchemaManagerException("Missing " + VALUE_TYPE_ID);
                String vDescr = vObj.optString(DESCR_ATTR_ID);
                logger.fine("Found " + value + " of type " + vType);
                result.add(new SPIDAttributeValue(value, vType, vDescr));
            }
            return result;

        } catch (JSONException jEx) {
            logger.log(Level.SEVERE, jEx.getMessage(), jEx);
            throw new SchemaManagerException(jEx.getMessage());
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