package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

public class GroupSearchResult {

    private int total;

    private List<GroupResource> users;

    public GroupSearchResult() {
        total = 0;
        users = new ArrayList<GroupResource>();
    }

    public GroupSearchResult(int initCap) {
        total = 0;
        users = new ArrayList<GroupResource>(initCap);
    }

    public void add(GroupResource user) {
        users.add(user);
    }

    public List<GroupResource> getGroupList() {
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