package it.infn.security.saml.listener;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.wso2.charon.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon.core.encoder.json.JSONDecoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.AttributeSchema;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;

public class SCIMListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(IdentityListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

        try {

            logger.log(Level.INFO, "Registering codecs");
            AbstractResourceEndpoint.registerEncoder(SCIMConstants.JSON, new JSONEncoder());
            AbstractResourceEndpoint.registerDecoder(SCIMConstants.JSON, new JSONDecoder());

            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            String extSchemaPath = config.getExtensionSchemaPath();
            logger.log(Level.INFO, "Loading extension schema from " + extSchemaPath);
            SCIMUserSchemaExtensionBuilder.getInstance().buildUserSchemaExtension(extSchemaPath);

            /*
             * TODO workaround for subAttributes/attributes mismatch in complex
             * multivalued extensions
             */
            SCIMResourceSchema resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
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

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

    public void contextDestroyed(ServletContextEvent event) {
    }

}