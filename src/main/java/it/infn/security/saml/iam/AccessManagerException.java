package it.infn.security.saml.iam;

import it.infn.security.saml.aa.CodedException;

public class AccessManagerException
    extends CodedException {

    public static final long serialVersionUID = 1432298722;

    public AccessManagerException(String msg) {
        super(msg);
    }

    public AccessManagerException(String msg, int code) {
        super(msg, code);
    }

    public AccessManagerException(String msg, Throwable th) {
        super(msg, th);
    }

    public AccessManagerException(String msg, int code, Throwable th) {
        super(msg, code, th);
    }

}