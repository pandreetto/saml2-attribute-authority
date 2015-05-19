package it.infn.security.saml.handler;

import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;

public interface SAML2Handler {

    public void checkRequest(AttributeQuery query)
        throws SAML2HandlerException;

    public String getSubjectID(AttributeQuery query);

    public void fillInResponse(Response response, List<Attribute> attributes, AttributeQuery query)
        throws SAML2HandlerException;

}