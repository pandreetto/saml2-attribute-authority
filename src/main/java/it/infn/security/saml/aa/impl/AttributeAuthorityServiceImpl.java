package it.infn.security.saml.aa.impl;

import it.infn.security.saml.aa.AttributeAuthorityService;
import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.AttributeQueryParameters;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;
import it.infn.security.saml.utils.SAML2ObjectBuilder;
import it.infn.security.saml.utils.SignUtils;

import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.xml.signature.Signature;

public class AttributeAuthorityServiceImpl
    implements AttributeAuthorityService {

    private static final Logger logger = Logger.getLogger(AttributeAuthorityServiceImpl.class.getName());

    public Response attributeQuery(AttributeQuery query) {

        Response response = SAML2ObjectBuilder.buildResponse();
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(query.getID());

        try {

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            DataSource dataSource = DataSourceFactory.getDataSource();

            response.setID(schemaManager.generateResponseID());

            Issuer responseIssuer = SAML2ObjectBuilder.buildIssuer();
            responseIssuer.setFormat(schemaManager.getAuthorityIDFormat());
            responseIssuer.setValue(configuration.getAuthorityID());
            response.setIssuer(responseIssuer);

            if (query.getVersion() != SAMLVersion.VERSION_20) {
                throw new CodedException("Unsupported version", StatusCode.VERSION_MISMATCH_URI);
            }

            schemaManager.checkRequest(query);

            Subject requester = identityManager.authenticate();

            Signature signature = query.getSignature();
            if (signature == null && schemaManager.requiredSignedQuery()) {
                throw new CodedException("Missing signature in query", StatusCode.RESPONDER_URI);
            }
            if (signature != null) {
                SignUtils.verifySignature(signature, requester);
            }

            String samlId = query.getSubject().getNameID().getValue();
            String userId = dataSource.samlId2UserId(samlId);
            if (userId == null) {
                throw new DataSourceException("User not found", StatusCode.RESPONDER_URI,
                        StatusCode.UNKNOWN_PRINCIPAL_URI);
            }

            AttributeQueryParameters params = new AttributeQueryParameters(userId);
            AccessConstraints constraints = accessManager.authorizeAttributeQuery(requester, params);

            List<Attribute> queryAttrs = constraints.filterAttributes(query.getAttributes());
            List<Attribute> userAttrs = dataSource.findAttributes(userId, queryAttrs);

            String respDestination = schemaManager.getResponseDestination();
            if (respDestination != null) {
                response.setDestination(respDestination);
            }

            /* Building the assertion */
            /*
             * TODO verify multiple assertions in response
             */
            Assertion assertion = SAML2ObjectBuilder.buildAssertion();
            assertion.setID(schemaManager.generateAssertionID());
            assertion.setIssueInstant(new DateTime());

            org.opensaml.saml2.core.Subject assertionSubject = SAML2ObjectBuilder.buildSubject();
            NameID sbjNameID = SAML2ObjectBuilder.buildNameID();
            sbjNameID.setFormat(query.getSubject().getNameID().getFormat());
            sbjNameID.setNameQualifier(configuration.getAuthorityQualifierName());
            sbjNameID.setValue(query.getSubject().getNameID().getValue());
            assertionSubject.setNameID(sbjNameID);
            assertion.setSubject(assertionSubject);

            Issuer assertionIssuer = SAML2ObjectBuilder.buildIssuer();
            assertionIssuer.setFormat(schemaManager.getAuthorityIDFormat());
            assertionIssuer.setValue(configuration.getAuthorityID());
            assertion.setIssuer(assertionIssuer);

            AttributeStatement attributeStatement = SAML2ObjectBuilder.buildAttributeStatement();
            attributeStatement.getAttributes().addAll(userAttrs);
            assertion.getAttributeStatements().add(attributeStatement);

            String signAlgorithm = null;
            String digestAlgorithm = null;
            int signPolicy = configuration.getSignaturePolicy();
            if ((signPolicy & AuthorityConfiguration.SIGN_AUTHZ_DRIVEN) > 0) {
                /*
                 * TODO implement
                 */
            }
            if ((signPolicy & AuthorityConfiguration.SIGN_REQUEST_DRIVEN) > 0 && signAlgorithm == null) {
                signAlgorithm = signature.getSignatureAlgorithm();
                digestAlgorithm = SignUtils.extractDigestAlgorithm(signature);
            }

            if (schemaManager.requiredSignedAssertion()) {
                SignUtils.signObject(assertion, signAlgorithm, digestAlgorithm);
            }

            response.getAssertions().add(assertion);

            Status status = SAML2ObjectBuilder.buildStatus();
            StatusCode statusCode = SAML2ObjectBuilder.buildStatusCode();
            statusCode.setValue(StatusCode.SUCCESS_URI);
            status.setStatusCode(statusCode);
            response.setStatus(status);

            if (schemaManager.requiredSignedResponse()) {
                SignUtils.signObject(response, signAlgorithm, digestAlgorithm);
            }

        } catch (SchemaManagerException cEx) {

            if (response.getID() == null) {
                response.setID("_" + UUID.randomUUID().toString());
            }
            Status status = this.newStatus(cEx);
            response.setStatus(status);

        } catch (CodedException cEx) {

            Status status = this.newStatus(cEx);
            response.setStatus(status);

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

            Status status = this.newStatus(th);
            response.setStatus(status);

        }

        return response;

    }

    private Status newStatus(Throwable th) {

        Status status = SAML2ObjectBuilder.buildStatus();

        if (th.getMessage() != null) {
            StatusMessage statusMessage = SAML2ObjectBuilder.buildStatusMessage();
            statusMessage.setMessage(th.getMessage());
            status.setStatusMessage(statusMessage);
        }

        StatusCode statusCode = SAML2ObjectBuilder.buildStatusCode();

        if (th instanceof CodedException) {
            CodedException handlerEx = (CodedException) th;
            statusCode.setValue(handlerEx.getStatusCode());

            String subCode = handlerEx.getSubStatusCode();
            if (subCode != null) {
                StatusCode subStatusCode = SAML2ObjectBuilder.buildStatusCode();
                subStatusCode.setValue(subCode);
                statusCode.setStatusCode(subStatusCode);
            }

        } else {
            statusCode.setValue(StatusCode.RESPONDER_URI);
        }

        status.setStatusCode(statusCode);

        return status;

    }

}
