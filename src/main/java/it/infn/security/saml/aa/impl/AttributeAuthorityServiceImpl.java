package it.infn.security.saml.aa.impl;

import it.infn.security.saml.aa.AttributeAuthorityService;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.handler.SAML2Handler;
import it.infn.security.saml.handler.SAML2HandlerException;
import it.infn.security.saml.handler.SAML2HandlerFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;

import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class AttributeAuthorityServiceImpl
    implements AttributeAuthorityService {

    public Response attributeQuery(AttributeQuery query) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer responseIssuer = issuerBuilder.buildObject();

        try {

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();

            identityManager.authenticate();

            accessManager.authorizeAttributeQuery(query);

            response.setID("_" + UUID.randomUUID().toString());
            response.setIssueInstant(new DateTime());
            response.setInResponseTo(query.getID());

            responseIssuer.setFormat(configuration.getAuthorityIDFormat());
            responseIssuer.setValue(configuration.getAuthorityID());
            response.setIssuer(responseIssuer);

            DataSource dataSource = DataSourceFactory.getDataSource();
            SAML2Handler handler = SAML2HandlerFactory.getHandler();

            handler.checkRequest(query);

            String sbjID = handler.getSubjectID(query);

            List<Attribute> userAttrs = dataSource.findAttributes(sbjID, null);

            handler.fillInResponse(response, userAttrs, query);

        } catch (Throwable th) {

            StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
            Status status = statusBuilder.buildObject();

            if (th.getMessage() != null) {
                StatusMessageBuilder statusMessageBuilder = (StatusMessageBuilder) builderFactory
                        .getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
                StatusMessage statusMessage = statusMessageBuilder.buildObject();
                statusMessage.setMessage(th.getMessage());
                status.setStatusMessage(statusMessage);
            }

            status.setStatusCode(getStatusCode(th));

            response.setStatus(status);

        }

        return response;

    }

    private StatusCode getStatusCode(Throwable th) {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();

        /*
         * TODO handle specific exceptions
         */
        if (th.getClass() == SAML2HandlerException.class) {
            SAML2HandlerException handlerEx = (SAML2HandlerException) th;
            statusCode.setValue(handlerEx.getStatusCode());

            String subCode = handlerEx.getSubStatusCode();
            if (subCode != null) {
                StatusCode subStatusCode = statusCodeBuilder.buildObject();
                subStatusCode.setValue(subCode);
                statusCode.setStatusCode(subStatusCode);
            }

        } else {
            statusCode.setValue(StatusCode.RESPONDER_URI);
        }

        return statusCode;
    }

}
