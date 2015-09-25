package it.infn.security.saml.ocp;

import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;

import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;

public class SPIDSchemaManager
    implements SchemaManager {

    public static final String SPID_ATTR_URI = "urn:it:infn:security:saml2:attributes:1.0";

    public static final String SPID_SCHEMA_URI = "urn:it:infn:security:saml2:attributes:1.0";

    public static final String NAME_ATTR_ID = "name";

    public static final String VALUE_ATTR_ID = "value";

    public static final String DESCR_ATTR_ID = "description";

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
            rootObject.put(NAME_ATTR_ID, attribute.getName().getName());

            JSONArray arrayObject = new JSONArray();
            for (AttributeValueInterface value : attribute) {
                JSONObject attrObject = new JSONObject();
                attrObject.put(VALUE_ATTR_ID, value.encode(format));
                attrObject.put(DESCR_ATTR_ID, value.getDescription());
                arrayObject.put(attrObject);
            }
            rootObject.put(ROOT_ATTR_ID, arrayObject);

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
                arrayObject.put(name.getName());
            }
            rootObject.put(NAME_ATTR_ID, arrayObject);
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

        return null;
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

        SCIMSubAttributeSchema descrSchema = SCIMSubAttributeSchema
                .createSCIMSubAttributeSchema(SPID_ATTR_URI, DESCR_ATTR_ID, SCIMSchemaDefinitions.DataType.STRING,
                        "Short attribute description", false, false, true);

        SCIMSubAttributeSchema[] subAttributes = new SCIMSubAttributeSchema[] { nameSchema, contentSchema, descrSchema };

        SCIMAttributeSchema rootSchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, ROOT_ATTR_ID,
                null, true, null, "Short attribute description", SPID_SCHEMA_URI, false, false, false, subAttributes);

        return rootSchema;
    }

}