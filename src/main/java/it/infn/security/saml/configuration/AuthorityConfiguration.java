package it.infn.security.saml.configuration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;

public interface AuthorityConfiguration {

    public void init(Map<String, String> parameters)
        throws ConfigurationException;

    public String getIdentityManagerClass()
        throws ConfigurationException;

    public String getAccessManagerClass()
        throws ConfigurationException;

    public String getDataSourceClass()
        throws ConfigurationException;

    public String getSAMLsHandlerClass()
        throws ConfigurationException;

    public String getAuthorityID()
        throws ConfigurationException;

    public String getAuthorityIDFormat()
        throws ConfigurationException;

    public String getDataSourceParam(String name)
        throws ConfigurationException;

    public X509Certificate getServiceCertificate()
        throws ConfigurationException;

    public PrivateKey getServicePrivateKey()
        throws ConfigurationException;

    public String getExtensionSchemaPath()
        throws ConfigurationException;

    public void close()
        throws ConfigurationException;

}