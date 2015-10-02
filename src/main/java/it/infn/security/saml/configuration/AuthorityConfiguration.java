package it.infn.security.saml.configuration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.ServiceLoader;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public interface AuthorityConfiguration {

    public void init(Map<String, String> parameters)
        throws ConfigurationException;

    public String getAuthorityID()
        throws ConfigurationException;

    public String getAuthorityIDFormat()
        throws ConfigurationException;

    public long getMetadataDuration()
        throws ConfigurationException;

    public String getSignatureAlgorithm()
        throws ConfigurationException;

    public String getDataSourceParam(String name)
        throws ConfigurationException;

    public String getDataSourceParam(String name, String defValue)
        throws ConfigurationException;

    public int getDataSourceParamAsInt(String name)
        throws ConfigurationException;

    public int getDataSourceParamAsInt(String name, int defValue)
        throws ConfigurationException;

    public String getAccessManagerParam(String name)
        throws ConfigurationException;

    public String getAccessManagerParam(String name, String defValue)
        throws ConfigurationException;

    public int getAccessManagerParamAsInt(String name)
        throws ConfigurationException;

    public int getAccessManagerParamAsInt(String name, int defValue)
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