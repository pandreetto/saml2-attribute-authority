package it.infn.security.saml.configuration.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.ConfigurationException;

import java.io.FileInputStream;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;

import org.opensaml.saml2.core.Issuer;

import eu.emi.security.authn.x509.impl.PEMCredential;

public class PropertyFileConfiguration
    implements AuthorityConfiguration {

    private static final String AUTHORITY_ID = "authority_id";

    private static final String AUTHORITY_ID_FORMAT = "authority_id_format";

    private static final String DATASOURCE_CLASS = "datasource_class";

    private static final String SAMLHANDLER_CLASS = "samlhandler_class";

    private static final String IDENTITY_MAN_CLASS = "identity_manager_class";

    private static final String ACCESS_MAN_CLASS = "access_manager_class";

    private static final String CERT_FILENAME = "service_certificate";

    private static final String KEY_FILENAME = "service_key";

    private Properties properties;

    private X509Certificate serviceCert = null;

    private PrivateKey serviceKey = null;

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

        String certFile = properties.getProperty(CERT_FILENAME);
        String pkFile = properties.getProperty(KEY_FILENAME);

        if (certFile != null && pkFile != null) {
            FileInputStream cis = null;
            FileInputStream kis = null;

            try {
                cis = new FileInputStream(certFile);
                kis = new FileInputStream(pkFile);

                PEMCredential credential = new PEMCredential(kis, cis, (char[]) null);
                serviceCert = credential.getCertificate();
                serviceKey = credential.getKey();

            } catch (Throwable th) {
                throw new ConfigurationException("Cannot load credentials", th);
            } finally {
                try {
                    cis.close();
                } catch (Exception ex) {
                    /*
                     * TODO log
                     */
                }

                try {
                    kis.close();
                } catch (Exception ex) {
                    /*
                     * TODO log
                     */
                }
            }
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
        String result = properties.getProperty(DATASOURCE_CLASS);
        if (result == null) {
            throw new ConfigurationException("Missing " + DATASOURCE_CLASS);
        }
        return result;
    }

    public String getSAMLsHandlerClass()
        throws ConfigurationException {
        String result = properties.getProperty(SAMLHANDLER_CLASS);
        if (result == null) {
            throw new ConfigurationException("Missing " + SAMLHANDLER_CLASS);
        }
        return result;
    }

    public String getAuthorityID()
        throws ConfigurationException {
        String result = properties.getProperty(AUTHORITY_ID);
        if (result == null) {
            throw new ConfigurationException("Missing " + AUTHORITY_ID);
        }
        return result;
    }

    public String getAuthorityIDFormat()
        throws ConfigurationException {
        return properties.getProperty(AUTHORITY_ID_FORMAT, Issuer.UNSPECIFIED);
    }

    public String getDataSourceParam(String name)
        throws ConfigurationException {
        String result = properties.getProperty(name);
        if (result == null) {
            throw new ConfigurationException("Missing " + name);
        }
        return result;
    }

    public X509Certificate getServiceCertificate()
        throws ConfigurationException {
        if (serviceCert == null) {
            throw new ConfigurationException("Missing " + CERT_FILENAME);
        }
        return serviceCert;
    }

    public PrivateKey getServicePrivateKey()
        throws ConfigurationException {
        if (serviceKey == null) {
            throw new ConfigurationException("Missing " + KEY_FILENAME);
        }
        return serviceKey;
    }

    public void close()
        throws ConfigurationException {

    }

}