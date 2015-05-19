package it.infn.security.saml.datasource;

import java.util.List;

import org.opensaml.saml2.core.Attribute;

public interface DataSource {

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs);

}