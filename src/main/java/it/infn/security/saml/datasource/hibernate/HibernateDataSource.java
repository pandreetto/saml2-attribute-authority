package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public class HibernateDataSource
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
                return null;
            }

            result = userFromEntity(session, usrEnt);
            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<User> listUsers()
        throws CharonException {
        return listUsers(null, null, null, -1, -1);
    }

    public List<User> listUsersByAttribute(Attribute attribute) {
        return null;
    }

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws CharonException {
        try {
            return listUsers(filter + operation + value, null, null, -1, -1);
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<User> listUsersBySort(String sortBy, String sortOrder) {
        try {
            return listUsers(null, sortBy, sortOrder, -1, -1);
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<User> listUsersWithPagination(int startIndex, int count) {
        try {
            return listUsers(null, null, null, startIndex, count);
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<User> listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException {

        count = HibernateUtils.checkQueryRange(count, true);

        ArrayList<User> result = new ArrayList<User>(count);

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
            eUser.setUserName(user.getUserName());
            eUser.setCommonName(user.getGivenName() + " " + user.getFamilyName());

            eUser.setAttributes(getExtendedAttributes(session, user));

            session.save(eUser);
            logger.info("Created user " + user.getUserName() + " with id " + user.getId());

            session.getTransaction().commit();

            return user;

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);

            session.getTransaction().rollback();

            throw new CharonException("Query execution error");
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
                return null;
            }

            result = groupFromEntity(session, grpEnt);
            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<Group> listGroups()
        throws CharonException {
        return listGroups(null, null, null, -1, -1);
    }

    public List<Group> listGroupsByAttribute(Attribute attribute)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws CharonException {
        return listGroups(filter + operation + value, null, null, -1, -1);
    }

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws CharonException {
        return listGroups(null, sortBy, sortOrder, -1, -1);
    }

    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        try {
            return listGroups(null, null, null, startIndex, count);
        } catch (CharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return null;
        }
    }

    public List<Group> listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws CharonException {

        count = HibernateUtils.checkQueryRange(count, false);

        ArrayList<Group> result = new ArrayList<Group>(count);

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
            grpEnt.setDisplayName(group.getDisplayName());

            grpEnt.setAttributes(getExtendedAttributes(session, group));

            session.save(grpEnt);
            logger.info("Created group " + grpEnt.getDisplayName() + " with id " + group.getId());

            updateMembers(session, grpEnt, group.getMembers());

            session.getTransaction().commit();

            return group;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

            session.getTransaction().rollback();

            throw new CharonException("Query execution error");
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

            /*
             * TODO lots fo queries, missing index on source
             */
            StringBuffer queryStr = new StringBuffer("SELECT qRes FROM ResourceEntity as qRes");
            queryStr.append(" INNER JOIN qRes.groups as rGroup WHERE rGroup.id=?");
            Query query = session.createQuery(queryStr.toString()).setString(0, grpEnt.getId());
            @SuppressWarnings("unchecked")
            List<ResourceEntity> members = query.list();

            for (ResourceEntity resEnt : members) {
                resEnt.getGroups().remove(grpEnt);
            }

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

    private User userFromEntity(Session session, UserEntity usrEnt)
        throws CharonException {
        User result = new User();
        result.setId(usrEnt.getId());
        result.setUserName(usrEnt.getUserName());

        HashSet<String> dGroups = getDirectGroupIds(session, usrEnt.getId());
        HashSet<String> iGroups = getIndirectGroupIds(session, dGroups);

        result.setDirectGroups(new ArrayList<String>(dGroups));
        result.setIndirectGroups(new ArrayList<String>(iGroups));

        return result;
    }

    private Group groupFromEntity(Session session, GroupEntity grpEnt)
        throws CharonException {
        Group result = new Group();
        result.setId(grpEnt.getId());
        result.setDisplayName(grpEnt.getDisplayName());

        StringBuffer queryStr = new StringBuffer("SELECT resource.id, resource.type");
        queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
        queryStr.append(" WHERE rGroups.id=?");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<Object[]> directMembers = (List<Object[]>) query.setString(0, grpEnt.getId()).list();
        for (Object[] tmpObj : directMembers) {
            if (tmpObj[1].equals(ResourceEntity.ResourceType.USER)) {
                result.setUserMember(tmpObj[0].toString());
            } else {
                result.setGroupMember(tmpObj[0].toString());
            }
        }

        return result;
    }

    private void updateMembers(Session session, ResourceEntity resEnt, List<String> memberIds) {

        /*
         * TODO check for cycles in the DAC
         */
        StringBuffer queryStr = new StringBuffer("FROM ResourceEntity as qRes");
        queryStr.append(" WHERE qRes.id in (:memberIds)");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> mResList = query.setParameterList("memberIds", memberIds).list();

        /*
         * TODO improve query
         */
        for (ResourceEntity tmpEnt : mResList) {
            tmpEnt.getGroups().add(resEnt);
            session.flush();
        }

    }

    /*
     * TODO move the section below into subclass
     */
    protected Set<AttributeEntity> getExtendedAttributes(Session session, AbstractSCIMObject resource)
        throws CharonException, NotFoundException {

        Set<AttributeEntity> result = new HashSet<AttributeEntity>();

        if (!resource.isAttributeExist(SPID_ATTR_NAME)) {
            return result;
        }

        Attribute extAttribute = resource.getAttribute(SPID_ATTR_NAME);
        for (Attribute subAttr : ((MultiValuedAttribute) extAttribute).getValuesAsSubAttributes()) {
            ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;
            SimpleAttribute keyAttr = (SimpleAttribute) cplxAttr.getSubAttribute(KEY_FIELD);
            SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(CONTENT_FIELD);
            SimpleAttribute descrAttr = (SimpleAttribute) cplxAttr.getSubAttribute(ATTR_DESCR_FIELD);

            AttributeEntity attrEnt = new AttributeEntity();
            AttributeEntityId attrEntId = new AttributeEntityId();
            attrEntId.setKey(keyAttr.getStringValue());
            attrEntId.setContent(cntAttr.getStringValue());
            attrEnt.setAttributeId(attrEntId);
            attrEnt.setDescription(descrAttr.getStringValue());

            /*
             * TODO check for attribute auto-saving
             */
            if (session.get(AttributeEntity.class, attrEntId) == null) {
                logger.info("Saving attribute " + attrEnt.getAttributeId().getKey());
                session.save(attrEnt);
            }

            result.add(attrEnt);

        }

        return result;
    }

}