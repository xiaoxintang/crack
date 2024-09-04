# emby macos
## 食用方法
-  客户端版本 Version 2.2.28 (25)
- 文件路径 `/Applications/Emby.app/Contents/Resources/www/modules/emby-apiclient/connectionmanager.js`

- 将 `connectionmanager.js` 文件替换原文件

## 原理
将`promise`的失败回调函数里的内容替换成正常的设置缓存

原来（格式化后）
    
```js
response => {
    var status = (response || {}).status;
    if (console.log("getRegistrationInfo response: " + status), 
    status && status < 500 && _servicelocator.appStorage.setItem(cacheKey, JSON.stringify({
        lastValidDate: -1,
        deviceId: params.deviceId,
        cacheExpirationDays: 0,
        lastUpdated: Date.now()
    })), 
    403 === status) 
        return Promise.reject("overlimit");
    if (status && status < 500) 
        return Promise.reject();
    status = response;
    if (
        console.log("getRegistrationInfo failed: " + status),
        regCacheValid) 
        return console.log("getRegistrationInfo returning cached info"), 
            Promise.resolve();
    throw status
}
```
    
按照前面resolve里的逻辑替换成

```js
response => {
    _servicelocator.appStorage.setItem(
        cacheKey,
        JSON.stringify({
            lastValidDate: Date.now(),
            deviceId: params.deviceId,
            cacheExpirationDays: 999,
            lastUpdated: Date.now(),
        })
    ), 
    Promise.resolve()
}
```

## 鸣谢
[@rartv](https://github.com/rartv)