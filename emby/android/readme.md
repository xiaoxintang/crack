# emby android
## 反编译
- 环境搭建
 ```shell
# 安装反编译工具
brew install apktool
# 生成签名文件。
# sign.keystore 是生成的文件名
# key0 是别名。好像也有用吧
keytool -genkey -v -keystore sign.keystore -alias key0 -keyalg RSA -keysize 2048 -validity 10000
```
- 反编译
```shell
apktool d apkname.apk
```
- 找到`connectionmanager.js`文件，替换原文件
- 编译
```shell
apktool b 反编译出来的文件目录 -o emby.unsign.apk
```
- 签名
```shell
# 到sdk目录
cd ~/Library/Android/sdk/build-tools/35.0.0
# 签名
apksigner sign --ks sign.keystore emby.unsign.apk
```
- 安装
```shell
adb install emby.unsign.apk
```