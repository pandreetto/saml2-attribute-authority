package it.infn.security.saml.ocp.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.hibernate.HibernateDataSource;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.UserEntity;
import it.infn.security.saml.ocp.SPIDAttributeName;
import it.infn.security.saml.ocp.SPIDAttributeValue;
import it.infn.security.saml.ocp.SPIDSchemaManager;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.schema.AttributeValueInterface;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.hibernate.Query;
import org.hibernate.Session;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;

public class SPIDDataSource
    extends HibernateDataSource {

    private static final Logger logger = Logger.getLogger(SPIDDataSource.class.getName());

    private Subject tenant;

    public SPIDDataSource() {
        super();
    }

    public int getLoadPriority() {
        return 0;
    }

    public DataSource getProxyDataSource(Subject tenant)
        throws DataSourceException {
        if (this.tenant != null)
            throw new DataSourceException("Cannot create proxy from data source");

        SPIDDataSource result = (SPIDDataSource) new SPIDDataSource();
        result.tenant = tenant;
        return result;
    }

    public Subject getTenant() {
        return tenant;
    }

    public List<AttributeNameInterface> getAttributeNames()
        throws DataSourceException {

        List<AttributeNameInterface> result = new ArrayList<AttributeNameInterface>();

        Session session = sessionFactory.getCurrentSession();
        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("SELECT DISTINCT qAttr.attributeId.key");
            queryStr.append(" FROM AttributeEntity as qAttr");
            Query query = session.createQuery(queryStr.toString());
            /*
             * TODO missing paging
             */
            @SuppressWarnings("unchecked")
            List<String> namesFound = query.list();

            for (String aName : namesFound) {
                /*
                 * TODO missing friendly name
                 */
                result.add(new SPIDAttributeName(aName, null));

            }

            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());
        }

        return result;
    }

    public AttributeEntry getAttribute(String name)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();
        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("FROM AttributeEntity as qAttr");
            queryStr.append(" WHERE qAttr.attributeId.key=?");
            Query query = session.createQuery(queryStr.toString());
            query.setString(0, name);

            @SuppressWarnings("unchecked")
            List<AttributeEntity> attrsFound = query.list();

            AttributeEntry result = new AttributeEntry(new SPIDAttributeName(name, null));
            for (AttributeEntity aEnt : attrsFound) {
                String value = aEnt.getAttributeId().getContent();
                result.add(new SPIDAttributeValue(value, aEnt.getType(), aEnt.getDescription()));
            }

            session.getTransaction().commit();

            return result;

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());
        }

    }

    public void createAttribute(AttributeEntry attribute)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            for (AttributeValueInterface vItem : attribute) {
                AttributeEntity aEnt = new AttributeEntity();
                AttributeEntityId aEntId = new AttributeEntityId();
                aEntId.setKey(attribute.getName().getNameId());
                aEntId.setContent((String) vItem.getValue());
                aEnt.setAttributeId(aEntId);
                aEnt.setDescription(vItem.getDescription());
                aEnt.setType(vItem.getType());
                session.save(aEnt);
            }

            session.getTransaction().commit();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());
        }
    }

    public void updateAttribute(AttributeEntry attribute)
        throws DataSourceException {

        /*
         * TODO improve update
         */
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            String name = attribute.getName().getNameId();

            StringBuffer queryStr = new StringBuffer("DELETE FROM AttributeEntity as qAttr");
            queryStr.append(" WHERE qAttr.attributeId.key=?");
            Query query = session.createQuery(queryStr.toString());
            query.setString(0, name);

            int count = query.executeUpdate();
            if (count == 0) {
                throw new DataSourceException("No name found " + name);
            }

            for (AttributeValueInterface vItem : attribute) {
                AttributeEntity aEnt = new AttributeEntity();
                AttributeEntityId aEntId = new AttributeEntityId();
                aEntId.setKey(attribute.getName().getNameId());
                aEntId.setContent((String) vItem.getValue());
                aEnt.setAttributeId(aEntId);
                aEnt.setDescription(vItem.getDescription());
                aEnt.setType(vItem.getType());
                session.save(aEnt);
            }

            session.getTransaction().commit();

        } catch (DataSourceException dEx) {
            session.getTransaction().rollback();
            throw dEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());
        }

    }

    public void removeAttribute(String name)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("DELETE FROM AttributeEntity as qAttr");
            queryStr.append(" WHERE qAttr.attributeId.key=?");
            Query query = session.createQuery(queryStr.toString());
            query.setString(0, name);

            int count = query.executeUpdate();
            if (count == 0) {
                throw new DataSourceException("No name found " + name);
            }

            session.getTransaction().commit();

        } catch (DataSourceException dEx) {
            session.getTransaction().rollback();
            throw dEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());
        }

    }

    protected List<Attribute> buildAttributeList(Session session, HashSet<String> allIds, List<Attribute> reqAttrs) {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        HashMap<String, Object> qArgs = new HashMap<String, Object>();
        StringBuffer queryStr = new StringBuffer("SELECT qAttributes");
        queryStr.append(" FROM ResourceEntity as qRes INNER JOIN qRes.attributes as qAttributes");

        queryStr.append(" WHERE qRes.id IN (:resourceIds)");
        qArgs.put("resourceIds", allIds);

        if (reqAttrs != null && reqAttrs.size() > 0) {
            queryStr.append(" AND (");
            int keyNum = 0;
            for (Attribute reqAttr : reqAttrs) {
                String tmpName = reqAttr.getName();
                List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                if (keyNum > 0) {
                    queryStr.append(" OR");
                }
                String keyTag = "key_" + keyNum;
                keyNum++;

                if (tmpValues != null && tmpValues.size() > 0) {
                    int cntNum = 0;
                    for (XMLObject xObj : tmpValues) {

                        if (cntNum > 0) {
                            queryStr.append(" OR");
                        }
                        String refValue = xObj.getDOM().getTextContent().trim();

                        queryStr.append(" (qAttributes.attributeId.key = :").append(keyTag);
                        qArgs.put(keyTag, tmpName);

                        String cntTag = "cnt_" + keyNum + "_" + cntNum;
                        queryStr.append(" AND qAttributes.attributeId.content = :");
                        queryStr.append(cntTag).append(")");
                        qArgs.put(cntTag, refValue);
                        cntNum++;
                    }
                } else {
                    queryStr.append(" qAttributes.attributeId.key = :").append(keyTag);
                    qArgs.put(keyTag, tmpName);
                }
            }

            queryStr.append(")");
        }

        Query query = session.createQuery(queryStr.toString());
        query.setProperties(qArgs);

        @SuppressWarnings("unchecked")
        List<AttributeEntity> filteredAttrs = query.list();

        HashMap<String, Attribute> resultTable = new HashMap<String, Attribute>();
        for (AttributeEntity attrEnt : filteredAttrs) {

            String attrKey = attrEnt.getAttributeId().getKey();
            Attribute attribute = null;
            if (resultTable.containsKey(attrKey)) {
                attribute = resultTable.get(attrKey);
            } else {
                attribute = attributeBuilder.buildObject();
                attribute.setName(attrKey);
                attribute.setNameFormat(Attribute.BASIC);
                resultTable.put(attrKey, attribute);
            }

            XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(attrEnt.getAttributeId().getContent());
            attribute.getAttributeValues().add(attributeValue);

        }

        for (Attribute tmpAttr : resultTable.values()) {
            result.add(tmpAttr);
        }

        return result;
    }

    protected Set<AttributeEntity> getExtendedAttributes(Session session, AbstractSCIMObject resource)
        throws CharonException, NotFoundException, DataSourceException {

        Set<AttributeEntity> result = new HashSet<AttributeEntity>();

        if (!resource.isAttributeExist(SPIDSchemaManager.ROOT_ATTR_ID)) {
            return result;
        }

        /*
         * TODO move schema validation in *ResourceEndpoint
         */
        org.wso2.charon.core.attributes.Attribute extAttribute = resource.getAttribute(SPIDSchemaManager.ROOT_ATTR_ID);
        if (extAttribute == null) {
            throw new CharonException("Missing attribute " + SPIDSchemaManager.ROOT_ATTR_ID);
        }
        List<org.wso2.charon.core.attributes.Attribute> allSubAttrs = ((MultiValuedAttribute) extAttribute)
                .getValuesAsSubAttributes();

        for (org.wso2.charon.core.attributes.Attribute subAttr : allSubAttrs) {

            ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;

            SimpleAttribute nameAttr = (SimpleAttribute) cplxAttr.getSubAttribute(SPIDSchemaManager.NAME_ATTR_ID);
            if (nameAttr == null) {
                throw new CharonException("Missing attribute " + SPIDSchemaManager.NAME_ATTR_ID);
            }
            SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(SPIDSchemaManager.VALUE_ATTR_ID);
            if (cntAttr == null) {
                throw new CharonException("Missing attribute " + SPIDSchemaManager.VALUE_ATTR_ID);
            }

            AttributeEntityId attrEntId = new AttributeEntityId();
            attrEntId.setKey(nameAttr.getStringValue());
            attrEntId.setContent(cntAttr.getStringValue());

            AttributeEntity attrEnt = (AttributeEntity) session.get(AttributeEntity.class, attrEntId);

            if (attrEnt == null) {
                throw new DataSourceException("Unknown " + attrEntId.getKey() + ": " + attrEntId.getContent());
            }

            logger.info("Saving attribute " + attrEnt.getAttributeId().getKey());
            result.add(attrEnt);

        }

        return result;
    }

    protected void fillinUserExtAttributes(Session session, AbstractSCIMObject resource, UserEntity uEnt)
        throws CharonException, NotFoundException, DataSourceException {
        uEnt.setAttributes(getExtendedAttributes(session, resource));
    }

    protected void fillinGroupExtAttributes(Session session, AbstractSCIMObject resource, GroupEntity gEnt)
        throws CharonException, NotFoundException, DataSourceException {
        gEnt.setAttributes(getExtendedAttributes(session, resource));
    }

    protected void cleanUserExtAttributes(Session session, UserEntity uEnt)
        throws DataSourceException {

        uEnt.getAttributes().clear();
        session.flush();

    }

    protected void cleanGroupExtAttributes(Session session, GroupEntity gEnt)
        throws DataSourceException {

        gEnt.getAttributes().clear();
        session.flush();

    }

}