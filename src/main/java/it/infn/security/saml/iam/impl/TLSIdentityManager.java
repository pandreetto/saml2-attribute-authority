package it.infn.security.saml.iam.impl;

import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerException;

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;

public class TLSIdentityManager
    implements IdentityManager {

    private static final Logger logger = Logger.getLogger(TLSIdentityManager.class.getName());

    public TLSIdentityManager() {

    }

    public void init()
        throws IdentityManagerException {

    }

    public Subject authenticate()
        throws IdentityManagerException {

        Message currMsg = PhaseInterceptorChain.getCurrentMessage();
        HttpServletRequest request = (HttpServletRequest) currMsg.get("HTTP.REQUEST");

        X509Certificate[] certificateChain = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");

        if (certificateChain == null || certificateChain.length == 0) {
            throw new IdentityManagerException("User not authenticated");
        }

        logger.info("User authenticated" + certificateChain[0].getSubjectX500Principal().getName());

        Subject result = new Subject();
        result.getPublicCredentials().add(certificateChain);
        return result;
    }

    public void close()
        throws IdentityManagerException {

    }

}