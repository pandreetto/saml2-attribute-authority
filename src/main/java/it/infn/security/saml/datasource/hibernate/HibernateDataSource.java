package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.ExternalIdEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceStatus;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public abstract class HibernateDataSource
    extends HibernateBaseDataSource {

    private static final Logger logger = Logger.getLogger(HibernateDataSource.class.getName());

    public HibernateDataSource() {
    }

    public User getUser(String userId)
        throws CharonException {

        User result = null;
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();
            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, userId);
            if (usrEnt == null) {
                logger.info("Entity not found " + userId);
            } else {
                result = userFromEntity(session, usrEnt);
            }
            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<User> listUsers()
        throws CharonException {
        return listUsers(null, null, null, -1, -1).getUserList();
    }

    public List<User> listUsersByAttribute(Attribute attribute) {
        return null;
    }

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws CharonException {
        try {
            return listUsers(filter + operation + value, null, null, -1, -1).getUserList();
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<User> listUsersBySort(String sortBy, String sortOrder) {
        try {
            return listUsers(null, sortBy, sortOrder, -1, -1).getUserList();
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<User> listUsersWithPagination(int startIndex, int count) {
        try {
            return listUsers(null, null, null, startIndex, count).getUserList();
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public UserSearchResult listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException {

        count = HibernateUtils.checkQueryRange(count, true);

        UserSearchResult result = new UserSearchResult(count);

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("FROM UserEntity as qUser");

            if (sortBy != null) {
                sortBy = HibernateUtils.convertSortedParam(sortBy, true);
                queryStr.append(" ORDER BY ").append(sortBy);
                if (sortOrder != null && sortOrder.equalsIgnoreCase("descending")) {
                    queryStr.append(" DESC");
                } else {
                    queryStr.append(" ASC");
                }
            }

            Query query = session.createQuery(queryStr.toString());
            if (startIndex >= 0)
                query.setFirstResult(startIndex);
            if (count > 0)
                query.setMaxResults(count);

            @SuppressWarnings("unchecked")
            List<UserEntity> usersFound = query.list();

            for (UserEntity usrEnt : usersFound) {
                result.add(userFromEntity(session, usrEnt));
            }

            Query query2 = session.createQuery("SELECT COUNT(*) FROM UserEntity as qUser");
            @SuppressWarnings("unchecked")
            Iterator<Long> totalUser = query2.list().iterator();
            if (totalUser.hasNext()) {
                result.setTotalResults(totalUser.next().intValue());
            }

            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }

        return result;
    }

    public User updateUser(User user)
        throws CharonException {
        return null;
    }

    public User updateUser(List<Attribute> updatedAttributes) {
        return null;
    }

    public void deleteUser(String userId)
        throws NotFoundException, CharonException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, userId);
            if (usrEnt == null) {
                logger.info("Entity not found " + userId);
                throw new NotFoundException();
            }

            session.delete(usrEnt);

            session.getTransaction().commit();

        } catch (AbstractCharonException chEx) {
            session.getTransaction().rollback();
            throw chEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new CharonException(th.getMessage(), th);
        }
    }

    public User createUser(User user)
        throws CharonException, DuplicateResourceException {
        return createUser(user, false);
    }

    public User createUser(User user, boolean isBulkUserAdd)
        throws CharonException, DuplicateResourceException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            UserEntity eUser = new UserEntity();
            /*
             * The uid is auto-generated by the SCIM parser
             * ServerSideValidator#validateCreatedSCIMObject(AbstractSCIMObject, SCIMResourceSchema)
             */
            eUser.setId(user.getId());
            eUser.setType(ResourceType.USER);
            eUser.setStatus(ResourceStatus.ACTIVE);
            eUser.setCreateDate(user.getCreatedDate());
            eUser.setModifyDate(user.getLastModified());
            eUser.setVersion(HibernateUtils.generateNewVersion(null));
            eUser.setUserName(user.getUserName());

            HibernateUtils.copyAttributesInEntity(user, eUser);

            String extId = user.getExternalId();
            if (extId != null && extId.length() > 0) {
                if (this.getTenant() == null) {
                    throw new DataSourceException("Datasource is not a proxy");
                }

                for (Principal tmpp : this.getTenant().getPrincipals()) {
                    ExternalIdEntity tmpEnt = new ExternalIdEntity();
                    tmpEnt.setTenant(tmpp.getName());
                    tmpEnt.setExtId(extId);
                    eUser.getExternalIds().add(tmpEnt);
                }
            }

            eUser.setAttributes(getExtendedAttributes(session, user));

            session.save(eUser);
            logger.info("Created user " + user.getUserName() + " with id " + user.getId());

            session.getTransaction().commit();

            return user;

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);

            session.getTransaction().rollback();

            throw new CharonException(th.getMessage());
        }
    }

    public Group getGroup(String groupId)
        throws CharonException {

        Group result = null;
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();
            GroupEntity grpEnt = (GroupEntity) session.get(GroupEntity.class, groupId);
            if (grpEnt == null) {
                logger.info("Entity not found " + groupId);
            } else {
                result = groupFromEntity(session, grpEnt);
            }
            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<Group> listGroups()
        throws CharonException {
        return listGroups(null, null, null, -1, -1).getGroupList();
    }

    public List<Group> listGroupsByAttribute(Attribute attribute)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws CharonException {
        return listGroups(filter + operation + value, null, null, -1, -1).getGroupList();
    }

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws CharonException {
        return listGroups(null, sortBy, sortOrder, -1, -1).getGroupList();
    }

    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        try {
            return listGroups(null, null, null, startIndex, count).getGroupList();
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public GroupSearchResult listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException {

        count = HibernateUtils.checkQueryRange(count, false);

        GroupSearchResult result = new GroupSearchResult(count);

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("FROM GroupEntity as qGroup");

            if (sortBy != null) {
                sortBy = HibernateUtils.convertSortedParam(sortBy, false);
                queryStr.append(" ORDER BY ").append(sortBy);
                if (sortOrder != null && sortOrder.equalsIgnoreCase("descending")) {
                    queryStr.append(" DESC");
                } else {
                    queryStr.append(" ASC");
                }
            }

            Query query = session.createQuery(queryStr.toString());
            if (startIndex >= 0)
                query.setFirstResult(startIndex);
            if (count > 0)
                query.setMaxResults(count);

            @SuppressWarnings("unchecked")
            List<GroupEntity> groupsFound = query.list();

            for (GroupEntity grpEnt : groupsFound) {
                result.add(groupFromEntity(session, grpEnt));
            }

            Query query2 = session.createQuery("SELECT COUNT(*) FROM GroupEntity as qGroup");
            @SuppressWarnings("unchecked")
            Iterator<Long> totalGroup = query2.list().iterator();
            if (totalGroup.hasNext()) {
                result.setTotalResults(totalGroup.next().intValue());
            }

            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }

        return result;
    }

    public Group createGroup(Group group)
        throws CharonException, DuplicateResourceException {
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            GroupEntity grpEnt = new GroupEntity();
            /*
             * The gid is auto-generated by the SCIM parser
             * ServerSideValidator#validateCreatedSCIMObject(AbstractSCIMObject, SCIMResourceSchema)
             */
            grpEnt.setId(group.getId());
            grpEnt.setType(ResourceType.GROUP);
            grpEnt.setStatus(ResourceStatus.ACTIVE);
            grpEnt.setCreateDate(group.getCreatedDate());
            grpEnt.setModifyDate(group.getLastModified());
            grpEnt.setVersion(HibernateUtils.generateNewVersion(null));
            grpEnt.setDisplayName(group.getDisplayName());

            grpEnt.setAttributes(getExtendedAttributes(session, group));

            String extId = group.getExternalId();
            if (extId != null && extId.length() > 0) {
                if (this.getTenant() == null) {
                    throw new DataSourceException("Datasource is not a proxy");
                }

                for (Principal tmpp : this.getTenant().getPrincipals()) {
                    ExternalIdEntity tmpEnt = new ExternalIdEntity();
                    tmpEnt.setTenant(tmpp.getName());
                    tmpEnt.setExtId(extId);
                    grpEnt.getExternalIds().add(tmpEnt);
                }
            }

            session.save(grpEnt);
            logger.info("Created group " + grpEnt.getDisplayName() + " with id " + group.getId());

            ResourceGraph rGraph = new ResourceGraph(session);
            rGraph.addMembers(grpEnt, group.getMembers());

            session.getTransaction().commit();

            return group;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

            session.getTransaction().rollback();

            throw new CharonException(th.getMessage());
        }

    }

    public Group updateGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group patchGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group updateGroup(List<Attribute> attributes)
        throws CharonException {
        return null;
    }

    public void deleteGroup(String groupId)
        throws NotFoundException, CharonException {
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();
            GroupEntity grpEnt = (GroupEntity) session.get(GroupEntity.class, groupId);
            if (grpEnt == null) {
                logger.info("Entity not found " + groupId);
                throw new NotFoundException();
            }

            ResourceGraph rGraph = new ResourceGraph(session);
            rGraph.removeGroupsForEntity(grpEnt);

            session.delete(grpEnt);
            session.getTransaction().commit();

        } catch (AbstractCharonException chEx) {
            session.getTransaction().rollback();
            throw chEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new CharonException(th.getMessage(), th);
        }
    }

    private String getExternalId(Session session, ResourceEntity resEnt)
        throws CharonException {

        if (this.getTenant() == null)
            return null;

        Set<Principal> principalSet = this.getTenant().getPrincipals(Principal.class);

        if (principalSet.size() > 0) {
            List<String> tenantNames = new ArrayList<String>(principalSet.size());
            for (Principal tmpp : principalSet) {
                tenantNames.add(tmpp.getName());
            }

            StringBuffer queryStr = new StringBuffer("SELECT qExtId FROM ResourceEntity as qRes");
            queryStr.append(" INNER JOIN qRes.externalIds as qExtId");
            queryStr.append(" WHERE qRes.id=:resourceid AND qExtId.tenant in (:tenantlist)");

            Query query = session.createQuery(queryStr.toString());
            query.setString("resourceid", resEnt.getId());
            query.setParameterList("tenantlist", tenantNames);

            @SuppressWarnings("unchecked")
            List<ExternalIdEntity> extIdList = query.list();

            if (extIdList.size() > 0) {
                return extIdList.get(0).getExtId();
            }

        }

        return null;

    }

    private User userFromEntity(Session session, UserEntity usrEnt)
        throws CharonException, DataSourceException {
        User result = new User();
        result.setId(usrEnt.getId());
        result.setUserName(usrEnt.getUserName());
        result.setCreatedDate(usrEnt.getCreateDate());
        result.setLastModified(usrEnt.getModifyDate());
        result.setVersion(usrEnt.getVersion());

        ResourceGraph graph = new ResourceGraph(session);
        HashSet<String> dGroups = graph.getDirectGroupIds(usrEnt.getId());
        HashSet<String> iGroups = graph.getIndirectGroupIds(dGroups);

        result.setDirectGroups(new ArrayList<String>(dGroups));
        result.setIndirectGroups(new ArrayList<String>(iGroups));

        String externalId = getExternalId(session, usrEnt);
        if (externalId != null)
            result.setExternalId(externalId);

        HibernateUtils.copyAttributesInUser(usrEnt, result);

        return result;
    }

    private Group groupFromEntity(Session session, GroupEntity grpEnt)
        throws CharonException {
        Group result = new Group();
        result.setId(grpEnt.getId());
        result.setDisplayName(grpEnt.getDisplayName());
        result.setCreatedDate(grpEnt.getCreateDate());
        result.setLastModified(grpEnt.getModifyDate());
        result.setVersion(grpEnt.getVersion());

        ResourceGraph rGraph = new ResourceGraph(session);
        for (ResourceGraph.MemberItem item : rGraph.getMembersForGroup(grpEnt)) {
            if (item.isaUser()) {
                result.setUserMember(item.getId());
            } else {
                result.setGroupMember(item.getId());
            }
        }

        String externalId = getExternalId(session, grpEnt);
        if (externalId != null)
            result.setExternalId(externalId);

        return result;
    }

    protected abstract Set<AttributeEntity> getExtendedAttributes(Session session, AbstractSCIMObject resource)
        throws CharonException, NotFoundException;

}