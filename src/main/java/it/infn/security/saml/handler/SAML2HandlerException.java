package it.infn.security.saml.handler;

import org.opensaml.saml2.core.StatusCode;

public class SAML2HandlerException
    extends Exception {

    public static final long serialVersionUID = 1432039307;

    public SAML2HandlerException(String msg, String code) {
        super(msg);
    }

    public SAML2HandlerException(String msg, String code, Throwable th) {
        super(msg, th);
    }

    public String getStatusCode() {
        return StatusCode.RESPONDER_URI;
    }

    public String getSubStatusCode() {
        return null;
    }
}