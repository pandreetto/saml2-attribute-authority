package it.infn.security.saml.iam.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;
import it.infn.security.saml.iam.AttributeQueryParameters;

import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClient;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.ActionType;
import org.opensaml.xacml.ctx.EnvironmentType;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResourceType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.SubjectType;
import org.opensaml.xacml.policy.AttributeAssignmentType;
import org.opensaml.xacml.policy.ObligationType;
import org.opensaml.xacml.policy.ObligationsType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;

/*
 * TODO missing cache
 */
public class XACMLAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(XACMLAccessManager.class.getName());

    public static final String CONN_TIMEOUT = "pdp.connection.timeout";

    public static final int DEF_CONN_TIMEOUT = 5000;

    public static final String MAX_CONN = "pdp.max.connection";

    public static final int DEF_MAX_CONN = 50;

    public static final String BUFFER_SIZE = "pdp.buffer.size";

    public static final int DEF_BUFFER_SIZE = 4096;

    public static final String PDP_LIST = "pdp.list";

    public static final String RESTORE_TIME = "pdp.restore.time";

    public static final int DEF_RESTORE_TIME = 3600000;

    private XACMLBuilderWrapper xBuilder;

    private SOAPClient soapClient;

    private RoundRobinPDPSelector pdpList;

    private String messageIssuerId;

    public int getLoadPriority() {
        return 0;
    }

    public void init()
        throws AccessManagerException {

        try {

            xBuilder = XACMLBuilderWrapper.getInstance();

            AuthorityConfiguration authConf = AuthorityConfigurationFactory.getConfiguration();
            X509KeyManager keyManager = authConf.getKeyManager();
            X509TrustManager trustManager = authConf.getTrustManager();
            int conTimeout = authConf.getAccessManagerParamAsInt(CONN_TIMEOUT, DEF_CONN_TIMEOUT);
            int maxRequests = authConf.getAccessManagerParamAsInt(MAX_CONN, DEF_MAX_CONN);
            int buffSize = authConf.getAccessManagerParamAsInt(BUFFER_SIZE, DEF_BUFFER_SIZE);

            String pdpListStr = authConf.getAccessManagerParam(PDP_LIST, "");
            long restoreTime = authConf.getAccessManagerParamAsInt(RESTORE_TIME, DEF_RESTORE_TIME);
            pdpList = new RoundRobinPDPSelector(pdpListStr, restoreTime);

            soapClient = buildSOAPClient(keyManager, trustManager, conTimeout, maxRequests, buffSize);

            messageIssuerId = authConf.getAuthorityID();

        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage());
        }
    }

    public void close()
        throws AccessManagerException {

    }

    public AccessConstraints authorizeAttributeQuery(Subject requester, AttributeQueryParameters queryParams)
        throws AccessManagerException {

        AccessConstraints result = new AccessConstraints();

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.QUERY_ATTR_ACTION_URI,
                    queryParams.getId());
            ObligationsType obsType = processRequest(xacmlRequest);
            fillinConstraints(result, obsType);
            return result;

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.CREATE_USER_ACTION_URI, messageIssuerId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.MODIFY_USER_ACTION_URI, userId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;

    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.DELETE_USER_ACTION_URI, userId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;

    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.SHOW_USER_ACTION_URI, userId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.LIST_USERS_ACTION_URI, messageIssuerId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.CREATE_GROUP_ACTION_URI, messageIssuerId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.MODIFY_GROUP_ACTION_URI, groupId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.DELETE_GROUP_ACTION_URI, groupId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.SHOW_GROUP_ACTION_URI, groupId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {

        try {

            RequestType xacmlRequest = buildRequest(requester, XACMLAAProfile.LIST_GROUPS_ACTION_URI, messageIssuerId);
            processRequest(xacmlRequest);

        } catch (AccessManagerException amEx) {
            throw amEx;
        } catch (Throwable th) {
            logger.log(Level.SEVERE, th.getMessage(), th);
            throw new AccessManagerException(th.getMessage(), th);
        }

        return null;
    }

    private SOAPClient buildSOAPClient(X509KeyManager keyManager, X509TrustManager trustManager, int conTimeout,
            int maxRequests, int buffSize) {

        /*
         * see org.glite.authz.pep.server.config.PEPDaemonIniConfigurationParser#processPDPConfiguration
         */
        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");
        httpClientBuilder.setConnectionTimeout(conTimeout);
        httpClientBuilder.setMaxTotalConnections(maxRequests);
        httpClientBuilder.setMaxConnectionsPerHost(maxRequests);
        httpClientBuilder.setReceiveBufferSize(buffSize);
        httpClientBuilder.setSendBufferSize(buffSize);

        if (keyManager != null && trustManager != null) {
            TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(httpClientBuilder.getMaxTotalConnections());
        return new HttpSOAPClient(httpClientBuilder.buildClient(), parserPool);

    }

    private ObligationsType processRequest(RequestType xacmlRequest)
        throws AccessManagerException {

        String samlRequestID = "_" + UUID.randomUUID().toString();

        SOAPMessageContext msgContext = new BasicSOAPMessageContext();
        msgContext.setCommunicationProfileId(XACMLAAProfile.XACML_SAML_PROFILE_URI);
        msgContext.setOutboundMessageIssuer(messageIssuerId);
        msgContext.setSOAPRequestParameters(new HttpSOAPRequestParameters(
                "http://www.oasis-open.org/committees/security"));

        XACMLAuthzDecisionQueryType samlRequest = xBuilder.buildDecisionQuery();
        samlRequest.setRequest(xacmlRequest);

        Issuer issuer = xBuilder.buildIssuer(Issuer.ENTITY);
        issuer.setValue(messageIssuerId);
        samlRequest.setIssuer(issuer);

        samlRequest.setID(samlRequestID);
        samlRequest.setIssueInstant(new DateTime());

        samlRequest.setInputContextOnly(false);
        samlRequest.setReturnContext(true);

        Body body = xBuilder.buildBody();
        body.getUnknownXMLObjects().add(samlRequest);

        Envelope envelope = xBuilder.buildEnvelope();
        envelope.setBody(body);

        msgContext.setOutboundMessage(envelope);

        for (String pdpEp = pdpList.getEndpoint(); pdpEp != null; pdpEp = pdpList.getEndpoint()) {

            try {
                logger.info("Contacting PDP " + pdpEp);
                soapClient.send(pdpEp, msgContext);
            } catch (SOAPException soapEx) {
                logger.fine("Cannot contact PDP " + pdpEp);
                pdpList.markDown(pdpEp);
                continue;
            } catch (SecurityException secEx) {
                logger.log(Level.FINE, "Security Exception from PDP " + pdpEp, secEx);
                pdpList.markDown(pdpEp);
                continue;
            }

            Envelope soapResponse = (Envelope) msgContext.getInboundMessage();
            Response samlResponse = (Response) soapResponse.getBody().getOrderedChildren().get(0);

            if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
                logger.warning("Response from PDP " + pdpEp + " does not contain any assertion");
                pdpList.markDown(pdpEp);
                continue;
            }
            if (samlResponse.getAssertions().size() > 1) {
                logger.warning("Response from PDP " + pdpEp + " contains more than 1 assertion");
                pdpList.markDown(pdpEp);
                continue;
            }

            Assertion samlAssertion = samlResponse.getAssertions().get(0);

            List<Statement> authzStatements = samlAssertion
                    .getStatements(XACMLAuthzDecisionStatementType.TYPE_NAME_XACML20);
            if (authzStatements == null || authzStatements.isEmpty()) {
                logger.warning("Response from PDP " + pdpEp + " does not contain any authorization statement");
                pdpList.markDown(pdpEp);
                continue;
            }
            if (authzStatements.size() > 1) {
                logger.warning("Response from PDP " + pdpEp + " contains more than 1 authorization statement");
                pdpList.markDown(pdpEp);
                continue;
            }

            XACMLAuthzDecisionStatementType authzStatement = (XACMLAuthzDecisionStatementType) authzStatements.get(0);
            ResponseType xacmlResponse = authzStatement.getResponse();
            ResultType xacmlResult = xacmlResponse.getResult();

            switch (xacmlResult.getDecision().getDecision()) {
            case Deny:
                throw new AccessManagerException("Authorization denied for request " + samlRequestID);
            case Indeterminate:
                throw new AccessManagerException("Authorization indeterminated for request " + samlRequestID);
            case NotApplicable:
                throw new AccessManagerException("Authorization not applicable for request " + samlRequestID);
            case Permit:
                logger.info("Authorized request " + samlRequestID);
            }

            return xacmlResult.getObligations();
        }

        throw new AccessManagerException("Authorization failed: no response from PDPs");

    }

    private void fillinConstraints(AccessConstraints constraints, ObligationsType obligations) {

        if (obligations == null)
            return;

        List<ObligationType> allOblig = obligations.getObligations();
        if (allOblig == null)
            return;

        for (ObligationType oblType : allOblig) {

            if (XACMLAAProfile.ATTR_FILTER_OBLI_URI.equals(oblType.getObligationId())) {
                for (AttributeAssignmentType aaType : oblType.getAttributeAssignments()) {
                    if (XACMLAAProfile.ATTR_FILTER_ID_URI.equals(aaType.getAttributeId())) {
                        constraints.addAttribute(aaType.getValue());
                    }
                }
            }

        }

    }

    private RequestType buildRequest(Subject subject, String actionUri, String resId) {
        RequestType xacmlRequest = xBuilder.buildRequest();

        ActionType action = xBuilder.buildAction();
        action.getAttributes().add(
                xBuilder.buildAttribute(XACMLAAProfile.ACTION_ID_URI, XACMLAAProfile.XSD_STRING, null, actionUri));
        xacmlRequest.setAction(action);

        EnvironmentType environ = xBuilder.buildEnviron();
        environ.getAttributes().add(
                xBuilder.buildAttribute(XACMLAAProfile.PROFILE_ID_URI, XACMLAAProfile.XSD_STRING, null,
                        XACMLAAProfile.PROFILE_ID_VALUE));
        xacmlRequest.setEnvironment(environ);

        ResourceType resource = xBuilder.buildResource(null);
        resource.getAttributes().add(
                xBuilder.buildAttribute(XACMLAAProfile.RESOURCE_ID_URI, XACMLAAProfile.XSD_STRING, null, resId));
        xacmlRequest.getResources().add(resource);

        String subjName = null;
        for (X500Principal authUser : subject.getPrincipals(X500Principal.class)) {
            subjName = authUser.getName();
            break;
        }

        if (subjName != null) {
            SubjectType subjType = xBuilder.buildSubject(null);
            subjType.getAttributes()
                    .add(xBuilder.buildAttribute(XACMLAAProfile.SUBJECT_ID_URI, XACMLAAProfile.XSD_X500NAME, null,
                            subjName));
            xacmlRequest.getSubjects().add(subjType);
        }
        return xacmlRequest;
    }

}
