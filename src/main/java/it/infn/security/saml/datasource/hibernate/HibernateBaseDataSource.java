package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;

import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.opensaml.saml2.core.Attribute;

public abstract class HibernateBaseDataSource
    implements DataSource {

    private static final Logger logger = Logger.getLogger(HibernateBaseDataSource.class.getName());

    protected static SessionFactory sessionFactory;

    public HibernateBaseDataSource() {
    }

    public void init()
        throws DataSourceException {

        try {

            StandardServiceRegistryBuilder serviceRegistryBuilder = new StandardServiceRegistryBuilder();
            serviceRegistryBuilder.applySettings(HibernateUtils.getHibernateConfig().getProperties());
            sessionFactory = HibernateUtils.getHibernateConfig().buildSessionFactory(serviceRegistryBuilder.build());

        } catch (Throwable th) {
            logger.log(Level.SEVERE, "Cannot initialize database", th);
            throw new DataSourceException("Cannot initialize database", th);
        }

    }

    public String samlId2UserId(String samlId)
        throws DataSourceException {
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            String qStr = "SELECT qUser.id FROM UserEntity as qUser WHERE qUser.userName = :uName";
            Query query = session.createQuery(qStr).setString("uName", samlId);
            String result = (String) query.uniqueResult();
            
            session.getTransaction().commit();
            return result;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());

        }
    }

    public List<Attribute> findAttributes(String userId, List<Attribute> requiredAttrs)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            ResourceGraph rGraph = new ResourceGraph(session);
            HashSet<String> allIds = rGraph.getAllGroupIds(userId);
            allIds.add(userId);

            List<Attribute> result = buildAttributeList(session, allIds, requiredAttrs);

            session.getTransaction().commit();

            return result;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());

        }

    }

    public void close()
        throws DataSourceException {

    }

    protected abstract List<Attribute> buildAttributeList(Session session, HashSet<String> allIds,
            List<Attribute> reqAttrs);

}