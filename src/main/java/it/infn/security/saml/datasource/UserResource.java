package it.infn.security.saml.datasource;

public interface UserResource {

    public String getUserId()
        throws DataSourceException;

}