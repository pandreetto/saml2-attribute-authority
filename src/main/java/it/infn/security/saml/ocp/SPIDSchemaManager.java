package it.infn.security.saml.ocp;

import java.util.ArrayList;
import java.util.List;

import org.wso2.charon.core.schema.AttributeSchema;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;

import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;

public class SPIDSchemaManager
    implements SchemaManager {

    public static final String SPID_ATTR_URI = "urn:it:infn:security:saml2:attributes:1.0";

    public static final String SPID_SCHEMA_URI = "urn:it:infn:security:saml2:attributes:1.0";
    
    public static final String KEY_ATTR_ID = "key";
    
    public static final String VALUE_ATTR_ID = "content";
    
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

        fixSubAttributes(groupSchema);
        fixSubAttributes(userSchema);

    }

    public SCIMResourceSchema getGroupSchema() {
        return groupSchema;
    }

    public SCIMResourceSchema getUserSchema() {
        return userSchema;
    }

    public void close()
        throws SchemaManagerException {

    }

    public int getLoadPriority() {
        return 0;
    }

    private SCIMAttributeSchema buildExtAttributeSchema() {

        SCIMSubAttributeSchema[] empty = null;

        SCIMAttributeSchema keySchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, KEY_ATTR_ID,
                SCIMSchemaDefinitions.DataType.STRING, false, null, "Key identifier", SPID_SCHEMA_URI, false, false,
                true, empty);

        SCIMAttributeSchema contentSchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, VALUE_ATTR_ID,
                SCIMSchemaDefinitions.DataType.STRING, false, null, "Content identifier", SPID_SCHEMA_URI, false,
                false, true, empty);

        SCIMAttributeSchema descrSchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, DESCR_ATTR_ID,
                SCIMSchemaDefinitions.DataType.STRING, false, null, "Short attribute description", SPID_SCHEMA_URI,
                false, false, true, empty);

        SCIMAttributeSchema[] subAttributes = new SCIMAttributeSchema[] { keySchema, contentSchema, descrSchema };

        SCIMAttributeSchema rootSchema = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI, ROOT_ATTR_ID,
                null, "Short attribute description", SPID_SCHEMA_URI, false, false, false, subAttributes);

        return rootSchema;
    }

    /*
     * Workaround for subAttributes/attributes mismatch in complex multivalued extensions
     */
    private void fixSubAttributes(SCIMResourceSchema resourceSchema) {
        List<AttributeSchema> attributeSchemas = resourceSchema.getAttributesList();
        for (AttributeSchema attributeSchema : attributeSchemas) {

            SCIMAttributeSchema tmpSchema = (SCIMAttributeSchema) attributeSchema;
            List<SCIMSubAttributeSchema> subAttributeSchemas = tmpSchema.getSubAttributes();
            List<SCIMAttributeSchema> topAttributeSchemas = tmpSchema.getAttributes();
            if (topAttributeSchemas != null && subAttributeSchemas == null) {
                subAttributeSchemas = new ArrayList<SCIMSubAttributeSchema>();
                for (SCIMAttributeSchema inAttr : topAttributeSchemas) {
                    SCIMSubAttributeSchema outAttr = SCIMSubAttributeSchema.createSCIMSubAttributeSchema(
                            inAttr.getURI(), inAttr.getName(), inAttr.getType(), inAttr.getDescription(),
                            inAttr.getReadOnly(), inAttr.getRequired(), inAttr.getCaseExact(), new String[0]);
                    subAttributeSchemas.add(outAttr);
                }
                tmpSchema.setSubAttributes(subAttributeSchemas);
            }
        }
    }
}