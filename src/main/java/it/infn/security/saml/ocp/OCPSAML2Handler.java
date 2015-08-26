package it.infn.security.saml.ocp;

import it.infn.security.saml.handler.SAML2Handler;
import it.infn.security.saml.handler.SAML2HandlerException;

import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class OCPSAML2Handler
    implements SAML2Handler {

    public OCPSAML2Handler() {

    }

    public int getLoadPriority() {
        return 0;
    }

    public void checkRequest(AttributeQuery query)
        throws SAML2HandlerException {

    }

    public String getSubjectID(AttributeQuery query) {
        return query.getSubject().getNameID().getValue();
    }

    public void fillInResponse(Response response, List<Attribute> attributes, AttributeQuery query)
        throws SAML2HandlerException {

        /*
         * TODO missing definition
         */
        response.setDestination("TBD");

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

        /* Building the assertion */
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID("_" + UUID.randomUUID().toString());
        assertion.setIssueInstant(new DateTime());

        Issuer assertionIssuer = issuerBuilder.buildObject();
        assertionIssuer.setValue("dummy issuer");
        assertionIssuer.setFormat(Issuer.UNSPECIFIED);
        assertion.setIssuer(assertionIssuer);

        Status status = statusBuilder.buildObject();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        status.setStatusCode(statusCode);

        AttributeStatementBuilder attributeStatementBuilder = (AttributeStatementBuilder) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
        attributeStatement.getAttributes().addAll(attributes);
        assertion.getAttributeStatements().add(attributeStatement);

        /* filling in the response */

        response.setStatus(status);
        response.getAssertions().add(assertion);

    }

}