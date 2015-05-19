package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;

public class DataSourceFactory {

    public static DataSource getDataSource() {
        return new DataSource() {
            public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs) {
                return new ArrayList<Attribute>();
            }
        };
    }

}