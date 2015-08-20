package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

import org.wso2.charon.core.objects.Group;

public class GroupSearchResult {

    private int total;

    private List<Group> users;

    public GroupSearchResult() {
        total = 0;
        users = new ArrayList<Group>();
    }

    public GroupSearchResult(int initCap) {
        total = 0;
        users = new ArrayList<Group>(initCap);
    }

    public void add(Group user) {
        users.add(user);
    }

    public List<Group> getGroupList() {
        return users;
    }

    public boolean isEmpty() {
        return users.isEmpty();
    }

    public void setTotalResults(int tot) {
        total = tot;
    }

    public int getTotalResults() {
        return total;
    }
}