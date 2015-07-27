package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.UserEntity;

import org.hibernate.cfg.Configuration;

public class HibernateUtils {

    private static Configuration hiberCfg = null;

    private static String[] hiberCfgMParams = { "hibernate.connection.driver_class", "hibernate.connection.url",
            "hibernate.connection.username", "hibernate.connection.password" };

    private static String[] hiberCfgOParams = { "hibernate.dialect", "hibernate.connection.pool_size",
            "hibernate.current_session_context_class", "hibernate.cache.provider_class", "hibernate.show_sql",
            "hibernate.hbm2ddl.auto" };

    public static Configuration getHibernateConfig()
        throws ConfigurationException {

        if (hiberCfg != null) {
            return hiberCfg;
        }

        synchronized (HibernateUtils.class) {

            if (hiberCfg == null) {
                AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

                hiberCfg = new Configuration();

                for (String param : hiberCfgMParams) {
                    String tmppar = config.getDataSourceParam(param);
                    if (tmppar == null) {
                        throw new ConfigurationException("Missing parameter " + param);
                    }
                    hiberCfg.setProperty(param, tmppar);
                }

                for (String param : hiberCfgOParams) {
                    String tmppar = config.getDataSourceParam(param);
                    if (tmppar != null) {
                        hiberCfg.setProperty(param, tmppar);
                    }
                }

                hiberCfg.addAnnotatedClass(ResourceEntity.class);
                hiberCfg.addAnnotatedClass(AttributeEntity.class);
                hiberCfg.addAnnotatedClass(UserEntity.class);
                hiberCfg.addAnnotatedClass(GroupEntity.class);
            }

        }

        return hiberCfg;

    }

}