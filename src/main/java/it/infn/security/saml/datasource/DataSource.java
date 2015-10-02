package it.infn.security.saml.datasource;

import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;

import java.util.List;
import java.util.ServiceLoader;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.Attribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.extensions.UserManager;

public interface DataSource
    extends UserManager {

    public void init()
        throws DataSourceException;

    public String samlId2UserId(String samlId)
        throws DataSourceException;

    public List<Attribute> findAttributes(String userId, List<Attribute> requiredAttrs)
        throws DataSourceException;

    public UserSearchResult listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException;

    public GroupSearchResult listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException;

    public List<AttributeNameInterface> getAttributeNames()
        throws DataSourceException;

    public AttributeEntry getAttribute(String name)
        throws DataSourceException;

    public void createAttribute(AttributeEntry attribute)
        throws DataSourceException;

    public void updateAttribute(AttributeEntry attribute)
        throws DataSourceException;

    public void removeAttribute(String name)
        throws DataSourceException;

    public void close()
        throws DataSourceException;

    public DataSource getProxyDataSource(Subject tenant)
        throws DataSourceException;

    public Subject getTenant();

    public int getLoadPriority();

    public static ServiceLoader<DataSource> dataSourceLoader = ServiceLoader.load(DataSource.class);

}