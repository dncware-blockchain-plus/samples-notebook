# 概要

このソフトウェアは、DNCWARE Blockchain+の[サンプルコード](https://github.com/dncware-blockchain-plus/samples)を実際に動作させるためのライブラリです。

[Jupyter](https://jupyter.org/)ノートブック環境上で、
ブロックチェーンを利用するサンプルコードを動作させることを目的としています。  

Jupyterノートブックの基本的な使用方法については、
[jupyter notebookのヒントをGoogleで検索する](https://www.google.com/search?q=jupyter+notebook)
などしてください。

サンプルコード自体はJupyterノートブック環境上で動作するものですが、
ほとんどのサンプルコードはブロックチェーンに接続する内容のため、
そのサンプルコードを動作させるためには接続先のブロックチェーンが別に必要となります。
ブロックチェーンの環境については、[弊社](https://www.global.toshiba/jp/products-solutions/ai-iot/blockchain/question.html)までお問い合わせください。

<br/>

# ライセンス

このソフトウェアは、MITライセンスで提供されます。

<br/>

# 事前準備

お手元のパソコンに下記のソフトウェアをインストールします。  
すでにインストール済みの場合は手順をスキップしてかまいません。  
うまくいかない場合は、[FAQ](./FAQ.md)が参考になるかもしれません。

### Pythonのインストール

下記ページからPythonをダウンロードしてインストールします。  

[https://www.python.org/downloads/](https://www.python.org/downloads/)
  
### Jupyterのインストール

下記ページの手順にしたがってJupyter Notebookをインストールします。

[https://jupyter.org/install](https://jupyter.org/install)

### Node.jsのインストール

下記ページからNode.jsをダウンロードしてインストールします。  

[https://nodejs.org/ja/download](https://nodejs.org/ja/download)

<br/>

# 初期セットアップ

### ソフトウェアのダウンロード
```
git clone https://github.com/dncware-blockchain-plus/samples-notebook.git
cd samples-notebook
npm install
```

### JavaScript KernelのJupyterへの登録
```
npm run install-jupyter-kernel
```

### jupyterの起動
```
jupyter notebook
```

### 動作確認

`jupyter`のブラウザ画面で、右上の`New`のプルダウンに`JavaScript(Node.js)`が表示されていることを確認します。

### 初期セットアップ（ステップ１）の実行

`jupyter`のブラウザ画面で、`setup/setup1.ipynb`を開いて実行します。  
ノートブックが正常に最後まで実行されると、ウォレットファイルが作成されます。

### ブロックチェーン上にドメインを作成する

ブロックチェーンの管理者にサンプルコード用のドメインの作成を依頼します。  
ステップ1で作成したウォレットのアドレスを管理者に伝え、管理者がドメインを作成するのを待ちます。  
ドメインが作成されたら、管理者からそのドメインのIDを連絡してもらいます。　

この手順の詳細は[DOMAIN.md](./DOMAIN.md)を参照してください。　

### 初期セットアップ（ステップ２）の実行

`jupyter`のブラウザ画面で、`setup/setup2.ipynb`を開いて、冒頭の設定項目の説明に従って、ノートブックを（必要に応じて）編集します。その後、ノートブックを実行します。  
設定が間違えている場合には接続確認が失敗するので、設定項目を修正した後、ノートブックを最初から再実行してください。  
ノートブックが正常に最後まで実行されると、接続先ブロックチェーンの設定が記憶されます。

### 初期セットアップ（ステップ３）の実行

`jupyter`のブラウザ画面で、`setup/setup3.ipynb`を開いて、冒頭の設定項目の説明に従って、ノートブックを編集します。その後、ノートブックを実行します。  
設定が間違えている場合には動作確認が失敗するので、設定項目を修正した後、ノートブックを最初から再実行してください。  
ノートブックが正常に最後まで実行されると、ドメインの設定が記憶されます。

### 初期セットアップ（ステップ４）の実行

`jupyter`のブラウザ画面で、`setup/setup4.ipynb`を開いて実行します。  
ノートブックが正常に最後まで実行されると、ドメイン内にサンプルコードが共通して使うユーザやコントラクトが作成されます。

<br/>

# サンプルコードの実行

`basic`, `advanced`, `practice`の各フォルダ下にある`*.ipynb`ファイルをノートブックで開いて実行します。  
想定される実行結果の例は、下記レポジトリにあります。
[https://github.com/dncware-blockchain-plus/samples](https://github.com/dncware-blockchain-plus/samples)
