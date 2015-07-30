package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Session;
import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
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
            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, Long.parseLong(userId));
            if (usrEnt == null) {
                logger.info("Entity not found " + userId);
                /*
                 * TODO empty list or error?
                 */
                // session.getTransaction().commit();
                throw new DataSourceException("User not found");
            }

            result = userFromEntity(session, usrEnt);
            session.getTransaction().commit();

        } catch (Throwable th) {
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<User> listUsers()
        throws CharonException {
        return null;
    }

    public List<User> listUsersByAttribute(Attribute attribute) {
        return null;
    }

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<User> listUsersBySort(String sortBy, String sortOrder) {
        return null;
    }

    public List<User> listUsersWithPagination(int startIndex, int count) {
        return null;
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
            eUser.setType(ResourceType.USER);
            eUser.setUserName(user.getUserName());
            eUser.setCommonName(user.getGivenName() + " " + user.getFamilyName());

            Set<AttributeEntity> eUserAttrs = new HashSet<AttributeEntity>();

            Attribute extAttribute = user.getAttribute(SPID_ATTR_NAME);
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

                eUserAttrs.add(attrEnt);

            }

            eUser.setAttributes(eUserAttrs);

            Long genId = (Long) session.save(eUser);
            logger.info("Created user " + user.getUserName() + " with id " + genId.toString());

            session.getTransaction().commit();

            return user;

        } catch (Throwable th) {

            /*
             * TODO check rollback
             */
            session.getTransaction().rollback();

            logger.log(Level.SEVERE, "Query execution error", th);
            throw new CharonException("Query execution error");
        }
    }

    public Group getGroup(String groupId)
        throws CharonException {
        return null;
    }

    public List<Group> listGroups()
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByAttribute(Attribute attribute)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        return null;
    }

    public Group createGroup(Group group)
        throws CharonException, DuplicateResourceException {
        return null;
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

    }

    private User userFromEntity(Session session, UserEntity usrEnt)
        throws CharonException {
        User result = new User();
        result.setId(usrEnt.getId().toString());
        result.setUserName(usrEnt.getUserName());

        HashSet<Long> dGroups = getDirectGroupIds(session, usrEnt.getId());
        HashSet<Long> iGroups = getIndirectGroupIds(session, dGroups);

        ArrayList<String> tmpl1 = new ArrayList<String>(dGroups.size());
        for (Long tmpId : dGroups) {
            tmpl1.add(tmpId.toString());
        }
        result.setDirectGroups(tmpl1);

        ArrayList<String> tmpl2 = new ArrayList<String>(iGroups.size());
        for (Long tmpId : iGroups) {
            tmpl2.add(tmpId.toString());
        }
        result.setIndirectGroups(tmpl2);
        return result;
    }

}