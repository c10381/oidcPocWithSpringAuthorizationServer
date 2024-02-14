# 使用Authorization-server實作oidc流程

## 說明
使用authorization server作為OIDC的idp與userEndpoint

## 目標
- [x] 後端服務可使用authorization_code(with PKCE)進行登入
- [x] SSO
- [ ] SLO(with [Back-Channel Logout Architecture](https://docs.spring.io/spring-security/reference/reactive/oauth2/login/logout.html#_back_channel_logout_architecture))
      -> Spring authorization server目前不支持，詳情請看[傳送門](https://github.com/spring-projects/spring-authorization-server/issues/1200)
- [ ] Angular with OIDC
- [ ] 前端logout(front-Channel Logout)
- [ ] 自定義userEndpoint [傳送門](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-userinfo.html)
- [ ] oidc自動發現/註冊機制 [傳送門](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-dynamic-client-registration.html)
- [ ] API驗證機制

## 環境說明
- Java 17
- Spring boot 3
- Angular 17

## 使用說明
1. 請調整`.host`檔案，新增以下資訊
```
127.0.0.1 auth-server
127.0.0.1 resource-server-1
127.0.0.1 resource-server-2
127.0.0.1 oidc-ui
```

2. 前端請根據以下指示調整 
   - 使用以下指令進行安裝 `npm i --legacy-peer-deps`
   - 預設執行`projects/sample`
   - 需調整前端oidc設定， 請變更`projects/sample/src/app/auth-code-flow.config.ts`
   - 預設使用以下網址操作：[http://oidc-ui:4200/home.html](http://oidc-ui:4200/home.html)
3. Spring-Authorization-server資訊如下
   - [http://auth-server:8080](http://auth-server:8080)
   - 帳號密碼：user/password
3. keycloak-Authorization-server資訊如下
   - 目前DB為h2，重啟會重新load`baeldung-realm.json`
   - [http://auth-server:8083](http://auth-server:8083)
   - 測試帳號密碼：user/pass
   - [admin頁面](http://auth-server:8083/auth/)，bael-admin/pass
