package it.infn.security.saml.configuration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public interface AuthorityConfiguration {

    public static final int SIGN_REQUEST_DRIVEN = 1;

    public static final int SIGN_AUTHZ_DRIVEN = 2;

    public void init(Map<String, String> parameters)
        throws ConfigurationException;

    public String getAuthorityID()
        throws ConfigurationException;

    public String getAuthorityQualifierName()
        throws ConfigurationException;

    public String getAuthorityURL()
        throws ConfigurationException;

    public ContactInfo[] getContacts()
        throws ConfigurationException;

    public OrganizationInfo getOrganization()
        throws ConfigurationException;

    public long getMetadataDuration()
        throws ConfigurationException;

    public String getSignatureAlgorithm()
        throws ConfigurationException;

    public String getDigestAlgorithm()
        throws ConfigurationException;

    public int getSignaturePolicy()
        throws ConfigurationException;

    public String getDataSourceParam(String name)
        throws ConfigurationException;

    public String getDataSourceParam(String name, String defValue)
        throws ConfigurationException;

    public int getDataSourceParamAsInt(String name)
        throws ConfigurationException;

    public int getDataSourceParamAsInt(String name, int defValue)
        throws ConfigurationException;

    public HashMap<String, Object> getDataSourceParamMap(String regex)
        throws ConfigurationException;

    public String getAccessManagerParam(String name)
        throws ConfigurationException;

    public String getAccessManagerParam(String name, String defValue)
        throws ConfigurationException;

    public int getAccessManagerParamAsInt(String name)
        throws ConfigurationException;

    public int getAccessManagerParamAsInt(String name, int defValue)
        throws ConfigurationException;

    public HashMap<String, Object> getAccessManagerParamMap(String regex)
        throws ConfigurationException;

    public X509KeyManager getKeyManager()
        throws ConfigurationException;

    public X509TrustManager getTrustManager()
        throws ConfigurationException;

    public X509Certificate getServiceCertificate()
        throws ConfigurationException;

    public PrivateKey getServicePrivateKey()
        throws ConfigurationException;

    public void close()
        throws ConfigurationException;

    public int getLoadPriority();

    public static ServiceLoader<AuthorityConfiguration> configurationLoader = ServiceLoader
            .load(AuthorityConfiguration.class);

}