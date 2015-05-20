package it.infn.security.saml.datasource;

import java.util.List;

import org.opensaml.saml2.core.Attribute;

public interface DataSource {

    public void init()
        throws DataSourceException;

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException;

    public void close()
        throws DataSourceException;

}