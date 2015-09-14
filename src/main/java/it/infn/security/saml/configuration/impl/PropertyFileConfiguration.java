package it.infn.security.saml.configuration.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.ConfigurationException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.security.SecurityHelper;

public class PropertyFileConfiguration
    implements AuthorityConfiguration {

    private static final Logger logger = Logger.getLogger(PropertyFileConfiguration.class.getName());

    private static final String AUTHORITY_ID = "authority.id";

    private static final String AUTHORITY_ID_FORMAT = "authority.id.format";

    private static final String KEYMAN_FILENAME = "key.manager.file";

    private static final String KEYMAN_TYPE = "key.manager.type";

    private static final String KEYMAN_PWD = "key.manager.password";

    private static final String TRUSTMAN_FILENAME = "trust.manager.file";

    private static final String TRUSTMAN_TYPE = "trust.manager.type";

    private static final String TRUSTMAN_PWD = "trust.manager.password";

    private static final String CERT_FILENAME = "service.certificate";

    private static final String KEY_FILENAME = "service.key";

    private static final String CONF_PROPERTY = "saml.aa.configuration.file";

    private static final String DEF_CONFFILE = "/etc/saml2-attribute-authority/configuration.xml";

    private Properties properties;

    private X509KeyManager keyManager = null;

    private X509TrustManager trustManager = null;

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

        FileInputStream fis1 = null;
        try {

            String ksType = properties.getProperty(KEYMAN_TYPE, KeyStore.getDefaultType());
            KeyStore ks = KeyStore.getInstance(ksType);
            char[] password = properties.getProperty(KEYMAN_PWD, "").toCharArray();
            fis1 = new FileInputStream(properties.getProperty(KEYMAN_FILENAME));
            ks.load(fis1, password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);

            for (KeyManager kItem : kmf.getKeyManagers()) {
                if (kItem instanceof X509KeyManager) {
                    keyManager = (X509KeyManager) kItem;
                    logger.info("Loaded key manager");
                    break;
                }
            }
            
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
        } finally {
            if (fis1 != null) {
                try {
                    fis1.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        FileInputStream fis2 = null;
        try {

            String ksType = properties.getProperty(TRUSTMAN_TYPE, KeyStore.getDefaultType());
            KeyStore ks = KeyStore.getInstance(ksType);
            char[] password = properties.getProperty(TRUSTMAN_PWD, "").toCharArray();
            fis2 = new FileInputStream(properties.getProperty(TRUSTMAN_FILENAME));
            ks.load(fis2, password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            for (TrustManager tItem : tmf.getTrustManagers()) {
                if (tItem instanceof X509TrustManager) {
                    trustManager = (X509TrustManager) tItem;
                    logger.info("Loaded trust manager");
                    break;
                }
            }

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
        } finally {
            if (fis2 != null) {
                try {
                    fis2.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        /*
         * TODO extract cert and key from keymanager
         */
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

    public String getDataSourceParam(String name, String defValue) {
        String result = properties.getProperty(name);
        if (result == null) {
            return defValue;
        }
        return result;
    }

    public int getDataSourceParamAsInt(String name)
        throws ConfigurationException {
        try {
            return Integer.parseInt(getDataSourceParam(name));
        } catch (NumberFormatException nEx) {
            throw new ConfigurationException("Attribute " + name + " is not an integer");
        }
    }

    public int getDataSourceParamAsInt(String name, int defValue)
        throws ConfigurationException {
        try {
            return Integer.parseInt(getDataSourceParam(name));
        } catch (Exception ex) {
            logger.warning("Missing or wrong attribute " + name + "; used default value");
            return defValue;
        }
    }

    public String getAccessManagerParam(String name)
        throws ConfigurationException {
        String result = properties.getProperty(name);
        if (result == null) {
            throw new ConfigurationException("Missing " + name);
        }
        return result;
    }

    public String getAccessManagerParam(String name, String defValue) {
        String result = properties.getProperty(name);
        if (result == null) {
            return defValue;
        }
        return result;
    }

    public int getAccessManagerParamAsInt(String name)
        throws ConfigurationException {
        try {
            return Integer.parseInt(getAccessManagerParam(name));
        } catch (NumberFormatException nEx) {
            throw new ConfigurationException("Attribute " + name + " is not an integer");
        }
    }

    public int getAccessManagerParamAsInt(String name, int defValue)
        throws ConfigurationException {
        try {
            return Integer.parseInt(getAccessManagerParam(name));
        } catch (Exception ex) {
            logger.warning("Missing or wrong attribute " + name + "; used default value");
            return defValue;
        }
    }

    public X509KeyManager getKeyManager()
        throws ConfigurationException {
        if (keyManager == null) {
            throw new ConfigurationException("Cannot load key manager");
        }
        return keyManager;
    }

    public X509TrustManager getTrustManager()
        throws ConfigurationException {
        if (trustManager == null) {
            throw new ConfigurationException("Cannot load trust manager");
        }
        return trustManager;
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
