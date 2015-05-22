package it.infn.security.saml.configuration;

import java.util.Map;

public interface AuthorityConfiguration {

    public void init(Map<String, String> parameters)
        throws ConfigurationException;

    public String getDataSourceClass()
        throws ConfigurationException;

    public String getSAMLsHandlerClass()
        throws ConfigurationException;

    public String getAuthorityID()
        throws ConfigurationException;

    public String getAuthorityIDFormat()
        throws ConfigurationException;

    public void close()
        throws ConfigurationException;

}