package it.infn.security.saml.datasource;

import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;

import java.util.List;
import java.util.ServiceLoader;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.Attribute;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public interface DataSource {

    public void init()
        throws DataSourceException;

    public String samlId2UserId(String samlId)
        throws DataSourceException;

    public List<Attribute> findAttributes(String userId, List<Attribute> requiredAttrs)
        throws DataSourceException;

    public User createUser(User user)
        throws DataSourceException;

    public User createUser(User user, boolean isBulkUserAdd)
        throws DataSourceException;

    public User getUser(String userId)
        throws DataSourceException;

    public List<User> listUsers()
        throws DataSourceException;

    public List<User> listUsersByAttribute(org.wso2.charon.core.attributes.Attribute attribute)
        throws DataSourceException;

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws DataSourceException;

    public List<User> listUsersBySort(String sortBy, String sortOrder)
        throws DataSourceException;

    public List<User> listUsersWithPagination(int startIndex, int count)
        throws DataSourceException;

    public User updateUser(User user)
        throws DataSourceException;

    public User updateUser(List<org.wso2.charon.core.attributes.Attribute> updatedAttributes)
        throws DataSourceException;

    public void deleteUser(String userId)
        throws DataSourceException;

    public UserSearchResult listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws DataSourceException;

    public Group createGroup(Group group)
        throws DataSourceException;

    public Group getGroup(String groupId)
        throws DataSourceException;

    public Group patchGroup(Group oldGroup, Group newGroup)
        throws DataSourceException;

    public List<Group> listGroups()
        throws DataSourceException;

    public List<Group> listGroupsByAttribute(org.wso2.charon.core.attributes.Attribute attribute)
        throws DataSourceException;

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws DataSourceException;

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws DataSourceException;

    public List<Group> listGroupsWithPagination(int startIndex, int count)
        throws DataSourceException;

    public Group updateGroup(Group oldGroup, Group newGroup)
        throws DataSourceException;

    public Group updateGroup(List<org.wso2.charon.core.attributes.Attribute> attributes)
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