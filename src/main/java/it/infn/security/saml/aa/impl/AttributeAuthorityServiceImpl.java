package it.infn.security.saml.aa.impl;

import it.infn.security.saml.aa.AttributeAuthorityService;

import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class AttributeAuthorityServiceImpl
    implements AttributeAuthorityService {

    public Response process(AttributeQuery arg1) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID("_" + UUID.randomUUID().toString());
        assertion.setIssueInstant(new DateTime());

        Issuer assertionIssuer = issuerBuilder.buildObject();
        assertionIssuer.setValue("dummy issuer");
        assertionIssuer.setFormat(Issuer.UNSPECIFIED);
        assertion.setIssuer(assertionIssuer);

        Response response = responseBuilder.buildObject();
        response.setID("_" + UUID.randomUUID().toString());
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(arg1.getID());

        response.getAssertions().add(assertion);

        return response;
    }

}
