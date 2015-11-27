package it.infn.security.saml.iam.impl;

import it.infn.security.saml.aa.AttributeAuthorityServlet;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerException;

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;

public class TLSIdentityManager
    implements IdentityManager {

    private static final Logger logger = Logger.getLogger(TLSIdentityManager.class.getName());

    public TLSIdentityManager() {

    }

    public int getLoadPriority() {
        return 0;
    }

    public void init()
        throws IdentityManagerException {

    }

    /*
     * TODO change interface servlet, request as argument, move selection somewhere else
     */
    public Subject authenticate()
        throws IdentityManagerException {

        Message currMsg = PhaseInterceptorChain.getCurrentMessage();
        HttpServletRequest request = (HttpServletRequest) currMsg.get("HTTP.REQUEST");

        if (request == null) {
            request = AttributeAuthorityServlet.getCurrentRequest();
        }

        if (request == null) {
            throw new IdentityManagerException("Cannot retrieve current request");
        }

        X509Certificate[] certificateChain = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");

        if (certificateChain == null || certificateChain.length == 0) {
            throw new IdentityManagerException("User not authenticated");
        }

        X500Principal authUser = certificateChain[0].getSubjectX500Principal();
        logger.info("User authenticated" + authUser.getName());

        Subject result = new Subject();
        result.getPrincipals().add(authUser);
        result.getPublicCredentials().add(certificateChain);
        return result;
    }

    public void close()
        throws IdentityManagerException {

    }

}