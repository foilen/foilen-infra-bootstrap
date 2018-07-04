/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder(alphabetic = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class InfraLoginConfig {

    private String mysqlHostName;
    private int mysqlPort = 3306;
    private String mysqlDatabaseName;
    private String mysqlDatabaseUserName;
    private String mysqlDatabasePassword;

    private String cookieUserName;
    private String cookieDateName;
    private String cookieSignatureName;
    private String cookieSignatureSalt;

    private String csrfSalt;

    private String applicationId;

    private String fromEmail;
    private String administratorEmail;
    private String mailHost;
    private int mailPort = 25;
    private String mailUsername;
    private String mailPassword;

    private String loginBaseUrl;

    public String getAdministratorEmail() {
        return administratorEmail;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public String getCookieDateName() {
        return cookieDateName;
    }

    public String getCookieSignatureName() {
        return cookieSignatureName;
    }

    public String getCookieSignatureSalt() {
        return cookieSignatureSalt;
    }

    public String getCookieUserName() {
        return cookieUserName;
    }

    public String getCsrfSalt() {
        return csrfSalt;
    }

    public String getFromEmail() {
        return fromEmail;
    }

    public String getLoginBaseUrl() {
        return loginBaseUrl;
    }

    public String getMailHost() {
        return mailHost;
    }

    public String getMailPassword() {
        return mailPassword;
    }

    public int getMailPort() {
        return mailPort;
    }

    public String getMailUsername() {
        return mailUsername;
    }

    public String getMysqlDatabaseName() {
        return mysqlDatabaseName;
    }

    public String getMysqlDatabasePassword() {
        return mysqlDatabasePassword;
    }

    public String getMysqlDatabaseUserName() {
        return mysqlDatabaseUserName;
    }

    public String getMysqlHostName() {
        return mysqlHostName;
    }

    public int getMysqlPort() {
        return mysqlPort;
    }

    public void setAdministratorEmail(String administratorEmail) {
        this.administratorEmail = administratorEmail;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public void setCookieDateName(String cookieDateName) {
        this.cookieDateName = cookieDateName;
    }

    public void setCookieSignatureName(String cookieSignatureName) {
        this.cookieSignatureName = cookieSignatureName;
    }

    public void setCookieSignatureSalt(String cookieSignatureSalt) {
        this.cookieSignatureSalt = cookieSignatureSalt;
    }

    public void setCookieUserName(String cookieUserName) {
        this.cookieUserName = cookieUserName;
    }

    public void setCsrfSalt(String csrfSalt) {
        this.csrfSalt = csrfSalt;
    }

    public void setFromEmail(String fromEmail) {
        this.fromEmail = fromEmail;
    }

    public void setLoginBaseUrl(String loginBaseUrl) {
        this.loginBaseUrl = loginBaseUrl;
    }

    public void setMailHost(String mailHost) {
        this.mailHost = mailHost;
    }

    public void setMailPassword(String mailPassword) {
        this.mailPassword = mailPassword;
    }

    public void setMailPort(int mailPort) {
        this.mailPort = mailPort;
    }

    public void setMailUsername(String mailUsername) {
        this.mailUsername = mailUsername;
    }

    public void setMysqlDatabaseName(String mysqlDatabaseName) {
        this.mysqlDatabaseName = mysqlDatabaseName;
    }

    public void setMysqlDatabasePassword(String mysqlDatabasePassword) {
        this.mysqlDatabasePassword = mysqlDatabasePassword;
    }

    public void setMysqlDatabaseUserName(String mysqlDatabaseUserName) {
        this.mysqlDatabaseUserName = mysqlDatabaseUserName;
    }

    public void setMysqlHostName(String mysqlHostName) {
        this.mysqlHostName = mysqlHostName;
    }

    public void setMysqlPort(int mysqlPort) {
        this.mysqlPort = mysqlPort;
    }

}
