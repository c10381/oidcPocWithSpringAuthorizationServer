# 使用Spring-Authorization-server實作oidc流程

## 說明
使用Spring authorization server作為OIDC的idp與userEndpoint

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
1. 請將.host檔案新增以下資訊
```
127.0.0.1 auth-server
127.0.0.1 resource-server-1
127.0.0.1 resource-server-2
127.0.0.1 oidc-ui
```
2. 前端請使用以下指令進行安裝
`npm i --legacy-peer-deps`
預設會執行`projects/sample`
3. 需調整前端oidc設定， 請變更`projects/sample/src/app/auth-code-flow.config.ts`