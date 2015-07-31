package it.infn.security.saml.utils.charon;

import org.wso2.charon.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;

public class SCIMGroupSchemaManager {

    private static SCIMResourceSchema groupSchema = null;

    public static SCIMResourceSchema getSchema() {

        if (groupSchema == null) {
            synchronized (SCIMGroupSchemaManager.class) {
                if (groupSchema == null) {
                    SCIMAttributeSchema schemaExtension = SCIMUserSchemaExtensionBuilder.getInstance()
                            .getSCIMUserSchemaExtension();

                    if (schemaExtension != null) {
                        groupSchema = SCIMResourceSchema.createSCIMResourceSchema(SCIMConstants.GROUP,
                                SCIMConstants.CORE_SCHEMA_URI, SCIMConstants.GROUP_DESC, SCIMConstants.GROUP_ENDPOINT,
                                SCIMSchemaDefinitions.DISPLAY_NAME, SCIMSchemaDefinitions.MEMBERS, schemaExtension);

                    } else {
                        groupSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
                    }
                }
            }
        }

        return groupSchema;
    }
}