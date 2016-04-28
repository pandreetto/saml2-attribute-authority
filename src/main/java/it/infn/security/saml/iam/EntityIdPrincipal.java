package it.infn.security.saml.iam;

import java.security.Principal;

import org.opensaml.saml2.core.Issuer;

public class EntityIdPrincipal
    implements Principal {

    private String id;

    public EntityIdPrincipal(Issuer issuer) {
        id = issuer.getValue();
    }

    @Override
    public boolean equals(Object obj) {

        if (obj == null) {
            return false;
        }

        return id.equals(obj.toString());
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }

    public String getName() {
        return id;
    }
}