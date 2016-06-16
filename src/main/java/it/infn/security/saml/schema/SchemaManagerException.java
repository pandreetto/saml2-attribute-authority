package it.infn.security.saml.schema;

import it.infn.security.saml.aa.CodedException;

public class SchemaManagerException
    extends CodedException {

    public static final long serialVersionUID = 1440658374;

    public SchemaManagerException(String msg, int code) {
        super(msg, code);
    }

    public SchemaManagerException(String msg) {
        super(msg);
    }

    public SchemaManagerException(String msg, int code, Throwable th) {
        super(msg, code, th);
    }

    public SchemaManagerException(String msg, Throwable th) {
        super(msg, th);
    }

}