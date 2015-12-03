package it.infn.security.saml.configuration.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.configuration.ContactInfo;
import it.infn.security.saml.configuration.OrganizationInfo;

import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;

public class PropertyFileConfiguration
    implements AuthorityConfiguration {

    private static final Logger logger = Logger.getLogger(PropertyFileConfiguration.class.getName());

    private static final String AUTHORITY_ID = "authority.id";

    private static final String AUTHORITY_QNAME = "authority.qualifier.name";

    private static final String AUTHORITY_URL = "authority.url";

    private static final String KEYMAN_FILENAME = "key.manager.file";

    private static final String KEYMAN_TYPE = "key.manager.type";

    private static final String KEYMAN_PWD = "key.manager.password";

    private static final String KEYMAN_ALIAS = "key.manager.alias";

    private static final String TRUSTMAN_FILENAME = "trust.manager.file";

    private static final String TRUSTMAN_TYPE = "trust.manager.type";

    private static final String TRUSTMAN_PWD = "trust.manager.password";

    private static final String SIGN_ALGO = "signature.algorithm";

    private static final String DIGEST_ALGO = "digest.algorithm";

    private static final String SIGN_POLICY = "signature.policy";

    private static final String ASSER_DURATION = "assertion.duration";

    private static final String ASSER_OFFSET = "assertion.offset";

    private static final String META_EXP_TIME = "metadata.expiration_time";

    private static final String CONF_PROPERTY = "saml.aa.configuration.file";

    private static final String DEF_CONFFILE = "/etc/saml2-attribute-authority/configuration.conf";

    private static final Pattern CONTACT_PATTERN = Pattern.compile("contact.type.([\\w]+)");

    private static final Pattern ORGANIZ_PATTERN = Pattern.compile("organization.([\\w]+).(\\w\\w)");

    private Properties properties;

    private ContactInfo[] contacts;

    private OrganizationInfo organizInfo;

    private X509KeyManager keyManager = null;

    private X509TrustManager trustManager = null;

    private X509Certificate serviceCert = null;

    private PrivateKey serviceKey = null;

    private long assertionDuration;

    private long assertionOffsetTime;

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
            throw new ConfigurationException("Cannot load key manager");
        } finally {
            if (fis1 != null) {
                try {
                    fis1.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        if (keyManager == null) {
            throw new ConfigurationException("Missing key manager");
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
            throw new ConfigurationException("Cannot load trust manager");
        } finally {
            if (fis2 != null) {
                try {
                    fis2.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        if (trustManager == null) {
            throw new ConfigurationException("Missing trust manager");
        }

        String keyAlias = properties.getProperty(KEYMAN_ALIAS);

        serviceKey = keyManager.getPrivateKey(keyAlias);
        if (serviceKey == null)
            throw new ConfigurationException("Cannot extract private key from key manager");

        X509Certificate[] certChain = keyManager.getCertificateChain(keyAlias);
        if (certChain == null)
            throw new ConfigurationException("Cannot extract certificates from key manager");
        serviceCert = certChain[0];

        try {
            String tmps = properties.getProperty(ASSER_OFFSET, "0");
            assertionOffsetTime = Long.parseLong(tmps) * 1000;

            tmps = properties.getProperty(ASSER_DURATION, "3600");
            assertionDuration = Long.parseLong(tmps) * 1000;

            if (assertionDuration <= 0) {
                throw new ConfigurationException("Wrong assertion validity time parameters");
            }
        } catch (NumberFormatException nEx) {
            throw new ConfigurationException("Wrong assertion validity time parameters");
        }

        parseContacts();

        parseOrganization();

    }

    public String getAuthorityID()
        throws ConfigurationException {
        String result = properties.getProperty(AUTHORITY_ID);
        if (result == null) {
            throw new ConfigurationException("Missing " + AUTHORITY_ID);
        }
        return result;
    }

    public String getAuthorityQualifierName()
        throws ConfigurationException {
        return properties.getProperty(AUTHORITY_QNAME, getAuthorityID());
    }

    public String getAuthorityURL()
        throws ConfigurationException {
        String result = properties.getProperty(AUTHORITY_URL);
        if (result == null) {
            throw new ConfigurationException("Missing " + AUTHORITY_URL);
        }
        return result;
    }

    public ContactInfo[] getContacts()
        throws ConfigurationException {
        return contacts;
    }

    public OrganizationInfo getOrganization()
        throws ConfigurationException {
        return organizInfo;
    }

    public long getMetadataDuration()
        throws ConfigurationException {
        try {
            return Long.parseLong(properties.getProperty(META_EXP_TIME, "432000"));
        } catch (Exception ex) {
            return 432000;
        }
    }

    public String getSignatureAlgorithm()
        throws ConfigurationException {
        return properties.getProperty(SIGN_ALGO, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    }

    public String getDigestAlgorithm()
        throws ConfigurationException {
        return properties.getProperty(DIGEST_ALGO, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    }

    public int getSignaturePolicy()
        throws ConfigurationException {
        int result = 0;
        String[] methods = properties.getProperty(SIGN_POLICY, "").split(",");
        for (String method : methods) {
            if (method.equalsIgnoreCase("request_driven")) {
                result += SIGN_REQUEST_DRIVEN;
            } else if (method.equalsIgnoreCase("authorization_driven")) {
                result += SIGN_AUTHZ_DRIVEN;
            }
        }

        return result;
    }

    public long getAssertionDuration()
        throws ConfigurationException {
        return assertionDuration;
    }

    public long getAssertionOffsetTime()
        throws ConfigurationException {
        return assertionOffsetTime;
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

    public HashMap<String, Object> getDataSourceParamMap(String regex)
        throws ConfigurationException {
        HashMap<String, Object> result = new HashMap<String, Object>();
        Pattern pattern = Pattern.compile(regex);

        for (Object kName : properties.keySet()) {
            Matcher matcher = pattern.matcher(kName.toString());
            if (matcher.find()) {
                result.put(kName.toString(), properties.get(kName));
            }
        }

        return result;
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

    public HashMap<String, Object> getAccessManagerParamMap(String regex)
        throws ConfigurationException {
        HashMap<String, Object> result = new HashMap<String, Object>();
        return result;
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

    public X509Certificate getServiceCertificate() {
        return serviceCert;
    }

    public PrivateKey getServicePrivateKey() {
        return serviceKey;
    }

    public void close()
        throws ConfigurationException {

    }

    public int getLoadPriority() {
        return 0;
    }

    private void parseContacts() {
        ArrayList<ContactInfo> cList = new ArrayList<ContactInfo>();
        for (String tmpk : properties.stringPropertyNames()) {
            Matcher matcher = CONTACT_PATTERN.matcher(tmpk);
            if (matcher.matches()) {
                String cId = matcher.group(1);

                ContactInfo cInfo = new ContactInfo();
                cInfo.setType(properties.getProperty("contact.type." + cId));
                cInfo.setGivenName(properties.getProperty("contact.givenName." + cId, null));
                cInfo.setSurName(properties.getProperty("contact.surName." + cId, null));

                String emails = properties.getProperty("contact.emails." + cId, "");
                for (String tmps : emails.split(",")) {
                    cInfo.addEmail(tmps.trim());
                }

                String phones = properties.getProperty("contact.phones." + cId, "");
                for (String tmps : phones.split(",")) {
                    cInfo.addPhone(tmps.trim());
                }

                cList.add(cInfo);
            }
        }

        contacts = new ContactInfo[cList.size()];
        cList.toArray(contacts);

    }

    private void parseOrganization() {

        organizInfo = new OrganizationInfo();

        for (String tmpk : properties.stringPropertyNames()) {
            Matcher matcher = ORGANIZ_PATTERN.matcher(tmpk);
            if (matcher.matches()) {

                String tag = matcher.group(1);
                String lang = matcher.group(2);

                if (tag.equalsIgnoreCase("name")) {
                    organizInfo.setName(properties.getProperty(tmpk, ""), lang);
                    logger.info("Found organization name " + properties.getProperty(tmpk, ""));
                } else if (tag.equalsIgnoreCase("displayname")) {
                    organizInfo.setDisplayName(properties.getProperty(tmpk, ""), lang);
                } else if (tag.equalsIgnoreCase("url")) {
                    organizInfo.setURL(properties.getProperty(tmpk, ""), lang);
                }

            }

        }
    }

}
