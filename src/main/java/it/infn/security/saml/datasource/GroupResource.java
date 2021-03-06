package it.infn.security.saml.datasource;

import java.util.List;

public interface GroupResource
    extends Resource {

    public void setName(String name)
        throws DataSourceException;

    public String getName()
        throws DataSourceException;

    public void setUserMembers(List<String> idLists)
        throws DataSourceException;

    public List<String> getUMembers()
        throws DataSourceException;

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException;

    public List<String> getGMembers()
        throws DataSourceException;

    public List<String> getAllMembers()
        throws DataSourceException;

}