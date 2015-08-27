package it.infn.security.saml.configuration.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.ConfigurationException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.security.SecurityHelper;

public class PropertyFileConfiguration
    implements AuthorityConfiguration {

    private static final Logger logger = Logger.getLogger(PropertyFileConfiguration.class.getName());

    private static final String AUTHORITY_ID = "authority_id";

    private static final String AUTHORITY_ID_FORMAT = "authority_id_format";

    private static final String CERT_FILENAME = "service_certificate";

    private static final String KEY_FILENAME = "service_key";

    private static final String CONF_PROPERTY = "saml.aa.configuration.file";

    private static final String DEF_CONFFILE = "/etc/saml2-attribute-authority/configuration.xml";

    private Properties properties;

    private X509Certificate serviceCert = null;

    private PrivateKey serviceKey = null;

    public void init(Map<String, String> parameters)
        throws ConfigurationException {

        String filename = null;
        if (parameters.containsKey("conffile")) {
            filename = parameters.get("conffile");
        } else {
            filename = System.getProperty(CONF_PROPERTY, DEF_CONFFILE);
        }

        properties = new Properties();

        try {

            FileReader reader = new FileReader(filename);
            properties.load(reader);
            reader.close();

        } catch (Exception ex) {
            throw new ConfigurationException("Cannot load file " + filename, ex);
        }

        String certFile = properties.getProperty(CERT_FILENAME);
        String pkFile = properties.getProperty(KEY_FILENAME);

        if (certFile != null && pkFile != null) {
            BufferedInputStream bis = null;
            try {

                bis = new BufferedInputStream(new FileInputStream(certFile));
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                if (bis.available() > 0) {
                    serviceCert = (X509Certificate) cf.generateCertificate(bis);
                }

                serviceKey = SecurityHelper.decodePrivateKey(new File(pkFile), (char[]) null);

            } catch (Throwable th) {

                logger.log(Level.SEVERE, th.getMessage(), th);

            } finally {
                try {
                    bis.close();
                } catch (Throwable th) {

                }
            }
        }
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

    public int getLoadPriority() {
        return 0;
    }

}
