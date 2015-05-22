package it.infn.security.saml.handler;

import org.opensaml.saml2.core.StatusCode;

public class SAML2HandlerException
    extends Exception {

    public static final long serialVersionUID = 1432039307;

    private String code;

    private String subcode;

    public SAML2HandlerException(String msg, String code, String subcode) {
        super(msg);
        this.code = code;
        this.subcode = subcode;
    }

    public SAML2HandlerException(String msg, String code) {
        this(msg, code, (String) null);
    }

    public SAML2HandlerException(String msg) {
        this(msg, StatusCode.RESPONDER_URI, (String) null);
    }

    public SAML2HandlerException(String msg, String code, String subcode, Throwable th) {
        super(msg, th);
        this.code = code;
        this.subcode = subcode;
    }

    public SAML2HandlerException(String msg, String code, Throwable th) {
        this(msg, code, (String) null, th);
    }

    public SAML2HandlerException(String msg, Throwable th) {
        this(msg, StatusCode.RESPONDER_URI, (String) null, th);
    }

    public String getStatusCode() {
        return code;
    }

    public String getSubStatusCode() {
        return subcode;
    }
}