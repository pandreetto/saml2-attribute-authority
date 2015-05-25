package it.infn.security.saml.configuration.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.ConfigurationException;

import java.io.FileReader;
import java.util.Map;
import java.util.Properties;

import org.opensaml.saml2.core.Issuer;

public class PropertyFileConfiguration
    implements AuthorityConfiguration {

    private static final String AUTHORITY_ID = "authority_id";

    private static final String AUTHORITY_ID_FORMAT = "authority_id_format";

    private static final String DATASOURCE_CLASS = "datasource_class";

    private static final String SAMLHANDLER_CLASS = "samlhandler_class";

    private static final String IDENTITY_MAN_CLASS = "identity_manager_class";

    private static final String ACCESS_MAN_CLASS = "access_manager_class";

    private Properties properties;

    public void init(Map<String, String> parameters)
        throws ConfigurationException {

        if (!parameters.containsKey("conffile")) {
            throw new ConfigurationException("Missing configuration file in context");
        }

        String filename = parameters.get("conffile");
        properties = new Properties();

        try {

            FileReader reader = new FileReader(filename);
            properties.load(reader);
            reader.close();

        } catch (Exception ex) {
            throw new ConfigurationException("Cannot load file", ex);
        }
    }

    public String getIdentityManagerClass()
        throws ConfigurationException {
        return properties.getProperty(IDENTITY_MAN_CLASS, "it.infn.security.saml.iam.impl.TLSIdentityManager");
    }

    public String getAccessManagerClass()
        throws ConfigurationException {
        /*
         * TODO missing standard implementation
         */
        return properties.getProperty(ACCESS_MAN_CLASS, "");
    }

    public String getDataSourceClass()
        throws ConfigurationException {
        try {
            return properties.getProperty(DATASOURCE_CLASS);
        } catch (Exception ex) {
            throw new ConfigurationException("Missing " + DATASOURCE_CLASS);
        }
    }

    public String getSAMLsHandlerClass()
        throws ConfigurationException {
        try {
            return properties.getProperty(SAMLHANDLER_CLASS);
        } catch (Exception ex) {
            throw new ConfigurationException("Missing " + SAMLHANDLER_CLASS);
        }
    }

    public String getAuthorityID()
        throws ConfigurationException {
        try {
            return properties.getProperty(AUTHORITY_ID);
        } catch (Exception ex) {
            throw new ConfigurationException("Missing " + AUTHORITY_ID);
        }
    }

    public String getAuthorityIDFormat()
        throws ConfigurationException {
        return properties.getProperty(AUTHORITY_ID_FORMAT, Issuer.UNSPECIFIED);
    }

    public void close()
        throws ConfigurationException {

    }

}