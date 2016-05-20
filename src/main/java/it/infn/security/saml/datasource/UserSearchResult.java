package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

public class UserSearchResult {

    private int total;

    private List<UserResource> users;

    public UserSearchResult() {
        total = 0;
        users = new ArrayList<UserResource>();
    }

    public UserSearchResult(int initCap) {
        total = 0;
        users = new ArrayList<UserResource>(initCap);
    }

    public void add(UserResource user) {
        users.add(user);
    }

    public List<UserResource> getUserList() {
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