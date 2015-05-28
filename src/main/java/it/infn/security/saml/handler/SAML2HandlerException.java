package it.infn.security.saml.handler;

import it.infn.security.saml.aa.CodedException;

public class SAML2HandlerException
    extends CodedException {

    public static final long serialVersionUID = 1432039307;

    public SAML2HandlerException(String msg, String code, String subcode) {
        super(msg, code, subcode);
    }

    public SAML2HandlerException(String msg, String code) {
        super(msg, code);
    }

    public SAML2HandlerException(String msg) {
        super(msg);
    }

    public SAML2HandlerException(String msg, String code, String subcode, Throwable th) {
        super(msg, code, subcode, th);
    }

    public SAML2HandlerException(String msg, String code, Throwable th) {
        super(msg, code, th);
    }

    public SAML2HandlerException(String msg, Throwable th) {
        super(msg, th);
    }

}