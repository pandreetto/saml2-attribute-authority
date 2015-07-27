package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "groups")
public class GroupEntity
    extends ResourceEntity {

    @Column(nullable = false)
    private String displayName;

    public GroupEntity() {
    }

    public void setDisplayName(String dn) {
        displayName = dn;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean equals(Object other) {
        return super.equals(other);
    }

    public int hashCode() {
        return super.hashCode();
    }

}