package it.infn.security.saml.datasource;

import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;

import java.util.List;
import java.util.ServiceLoader;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.Attribute;

public interface DataSource {

    public void init()
        throws DataSourceException;

    public String samlId2UserId(String samlId)
        throws DataSourceException;

    public List<Attribute> findAttributes(String userId, List<Attribute> requiredAttrs)
        throws DataSourceException;

    public UserResource createUser(UserResource user)
        throws DataSourceException;

    public UserResource createUser(UserResource user, boolean isBulkUserAdd)
        throws DataSourceException;

    public UserResource getUser(String userId)
        throws DataSourceException;

    public List<UserResource> listUsers()
        throws DataSourceException;

    public List<UserResource> listUsersByFilter(String filter, String operation, String value)
        throws DataSourceException;

    public List<UserResource> listUsersBySort(String sortBy, String sortOrder)
        throws DataSourceException;

    public List<UserResource> listUsersWithPagination(int startIndex, int count)
        throws DataSourceException;

    public UserResource updateUser(UserResource user)
        throws DataSourceException;

    public void deleteUser(String userId)
        throws DataSourceException;

    public UserSearchResult listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws DataSourceException;

    public GroupResource createGroup(GroupResource group)
        throws DataSourceException;

    public GroupResource getGroup(String groupId)
        throws DataSourceException;

    public GroupResource patchGroup(GroupResource oldGroup, GroupResource newGroup)
        throws DataSourceException;

    public List<GroupResource> listGroups()
        throws DataSourceException;

    public List<GroupResource> listGroupsByFilter(String filter, String operation, String value)
        throws DataSourceException;

    public List<GroupResource> listGroupsBySort(String sortBy, String sortOrder)
        throws DataSourceException;

    public List<GroupResource> listGroupsWithPagination(int startIndex, int count)
        throws DataSourceException;

    public GroupResource updateGroup(GroupResource oldGroup, GroupResource newGroup)
        throws DataSourceException;

    public void deleteGroup(String groupId)
        throws DataSourceException;

    public GroupSearchResult listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws DataSourceException;

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