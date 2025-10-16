# FAQ

<br/>

## Pythonをインストールしてもpipがみつかりません

PATH環境変数が正しく設定されていない可能性があります。

[pipのPATH設定のヒントをGoogleで検索する](https://www.google.com/search?q=pip+PATH)

<br/>

## pip install がタイムアウトします

プロキシ環境下にある場合には、プロキシの設定が必要です。

Windowsのコマンドプロンプトの場合の例:
```
set http_proxy=http://proxy.mycompany.co.jp:8080
set https_proxy=http://proxy.mycompany.co.jp:8080
pip install jupyter
```

[pipのproxy設定のヒントをGoogleで検索する](https://www.google.com/search?q=pip+proxy)

<br/>

## npm installコマンドがタイムアウトします

プロキシ環境下にある場合には、プロキシの設定が必要です。  

WindowsのPowerShellの場合の例:
```
$env:http_proxy = "http://proxy.mycompany.co.jp:8080"
$env:https_proxy = "http://proxy.mycompany.co.jp:8080"
npm install
```