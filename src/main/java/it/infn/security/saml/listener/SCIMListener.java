package it.infn.security.saml.listener;

import it.infn.security.saml.schema.SchemaManagerFactory;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.wso2.charon.core.encoder.json.JSONDecoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;

public class SCIMListener
    implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(IdentityListener.class.getName());

    public void contextInitialized(ServletContextEvent event) {

        try {

            logger.log(Level.INFO, "Registering codecs");
            AbstractResourceEndpoint.registerEncoder(SCIMConstants.JSON, new JSONEncoder());
            AbstractResourceEndpoint.registerDecoder(SCIMConstants.JSON, new JSONDecoder());

            logger.log(Level.INFO, "Loading schema");
            SchemaManagerFactory.getManager();

            logger.log(Level.INFO, "SCIM initialization done");

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

    }

    public void contextDestroyed(ServletContextEvent event) {
    }

}