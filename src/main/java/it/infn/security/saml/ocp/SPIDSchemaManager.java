package it.infn.security.saml.ocp;

import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;

import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.opensaml.saml2.core.AttributeQuery;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;

public class SPIDSchemaManager
    implements SchemaManager {

    private static final Logger logger = Logger.getLogger(SPIDSchemaManager.class.getName());

    public static final String SPID_ATTR_URI = "urn:it:infn:security:saml2:attributes:1.0";

    public static final String SPID_SCHEMA_URI = "urn:it:infn:security:saml2:attributes:1.0";

    public static final String NAME_ATTR_ID = "name";

    public static final String NAME_FORMAT_ID = "format";

    public static final String NAME_FRIEND_ID = "friendlyname";

    public static final String VALUE_ATTR_ID = "value";

    public static final String VALUE_TYPE_ID = "type";

    public static final String DESCR_ATTR_ID = "description";

    public static final String VALUES_ATTR_ID = "values";

    public static final String NAMES_ATTR_ID = "names";

    public static final String ROOT_ATTR_ID = "SPIDAttributes";

    private SCIMResourceSchema groupSchema = null;

    private SCIMResourceSchema userSchema = null;

    public void init()
        throws SchemaManagerException {

        SCIMAttributeSchema schemaExtension = buildExtAttributeSchema();

        if (schemaExtension != null) {

            groupSchema = SCIMResourceSchema.createSCIMResourceSchema(SCIMConstants.GROUP,
                    SCIMConstants.CORE_SCHEMA_URI, SCIMConstants.GROUP_DESC, SCIMConstants.GROUP_ENDPOINT,
                    SCIMSchemaDefinitions.DISPLAY_NAME, SCIMSchemaDefinitions.MEMBERS, schemaExtension);

            userSchema = SCIMResourceSchema.createSCIMResourceSchema(SCIMConstants.USER, SCIMConstants.CORE_SCHEMA_URI,
                    SCIMConstants.USER_DESC, SCIMConstants.USER_ENDPOINT, SCIMSchemaDefinitions.USER_NAME,
                    SCIMSchemaDefinitions.NAME, SCIMSchemaDefinitions.DISPLAY_NAME, SCIMSchemaDefinitions.NICK_NAME,
                    SCIMSchemaDefinitions.PROFILE_URL, SCIMSchemaDefinitions.TITLE, SCIMSchemaDefinitions.USER_TYPE,
                    SCIMSchemaDefinitions.PREFERRED_LANGUAGE, SCIMSchemaDefinitions.LOCALE,
                    SCIMSchemaDefinitions.TIMEZONE, SCIMSchemaDefinitions.ACTIVE, SCIMSchemaDefinitions.PASSWORD,
                    SCIMSchemaDefinitions.EMAILS, SCIMSchemaDefinitions.PHONE_NUMBERS, SCIMSchemaDefinitions.IMS,
                    SCIMSchemaDefinitions.PHOTOS, SCIMSchemaDefinitions.ADDRESSES, SCIMSchemaDefinitions.GROUPS,
                    SCIMSchemaDefinitions.ENTITLEMENTS, SCIMSchemaDefinitions.ROLES,
                    SCIMSchemaDefinitions.X509CERTIFICATES, schemaExtension);
        } else {

            groupSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
            userSchema = SCIMSchemaDefinitions.SCIM_USER_SCHEMA;

        }

    }

    /*
     * SCIM section
     */

    public SCIMResourceSchema getGroupSchema() {
        return groupSchema;
    }

    public SCIMResourceSchema getUserSchema() {
        return userSchema;
    }

    public String encode(AttributeEntry attribute, String format)
        throws SchemaManagerException {

        if (!SCIMConstants.APPLICATION_JSON.endsWith(format)) {
            throw new SchemaManagerException("Unsupported format");
        }

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
            throw new SchemaManagerException("Cannot encode attribute");
        }
    }

    public String encode(List<AttributeNameInterface> names, String format)
        throws SchemaManagerException {

        if (!SCIMConstants.APPLICATION_JSON.endsWith(format)) {
            throw new SchemaManagerException("Unsupported format");
        }

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
            throw new SchemaManagerException("Cannot encode attribute");
        }

        return rootObject.toString();
    }

    public AttributeEntry parse(String data, String format)
        throws SchemaManagerException {

        if (!SCIMConstants.APPLICATION_JSON.endsWith(format)) {
            throw new SchemaManagerException("Unsupported format");
        }

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
            throw new SchemaManagerException(jEx.getMessage());
        }

    }

    /*
     * SAML2 section
     */

    public String[] getSupportedProtocols() {
        return new String[] { "urn:oasis:names:tc:SAML:2.0:protocol" };
    }

    public String[] getSupportedAttributeProfiles() {
        return new String[] { "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" };
    }

    public String[] getSupportedNameIDFormats() {
        return new String[] { "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" };
    }

    public void checkRequest(AttributeQuery query)
        throws SchemaManagerException {

    }

    public String getResponseDestination() {
        /*
         * TODO missing definition
         */
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

    private SCIMAttributeSchema buildExtAttributeSchema() {

        SCIMSubAttributeSchema nameSchema = SCIMSubAttributeSchema.createSCIMSubAttributeSchema(SPID_ATTR_URI,
                NAME_ATTR_ID, SCIMSchemaDefinitions.DataType.STRING, "Name identifier", false, false, true);

        SCIMSubAttributeSchema contentSchema = SCIMSubAttributeSchema.createSCIMSubAttributeSchema(SPID_ATTR_URI,
                VALUE_ATTR_ID, SCIMSchemaDefinitions.DataType.STRING, "Content identifier", false, false, true);

        SCIMSubAttributeSchema[] subAttributes = new SCIMSubAttributeSchema[] { nameSchema, contentSchema };

        SCIMAttributeSchema rootSchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, ROOT_ATTR_ID,
                null, true, null, "Short attribute description", SPID_SCHEMA_URI, false, false, false, subAttributes);

        return rootSchema;
    }

}