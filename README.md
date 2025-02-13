# ec2-bench

ec2-benchは、複数のAmazon EC2インスタンスタイプのパフォーマンスベンチマークを実行し、比較するためのPythonベースのツールです。このスクリプトは、インスタンスの起動、sysbenchテストの実行、結果の収集を自動化し、様々なEC2インスタンスタイプの仕様とパフォーマンスを簡単に比較できるようにします。

## 特徴

- 単一の実行で複数のEC2インスタンスタイプをサポート
- sysbenchを使用したCPU、メモリ、ファイルI/Oベンチマークの自動実行
- テストインスタンスでのカスタムスクリプト実行機能
- スポットインスタンスを使用したコスト効率の良いテスト
- 結果の分析と比較が容易なJSON形式の出力

## 前提条件

- Python 3.x
- boto3ライブラリ
- 適切な権限で設定されたAWS CLI
- インターネットアクセス可能なVPC

## インストール

1. このリポジトリをクローンします：
   ```
   git clone https://github.com/kawataki-yoshika/ec2-bench.git
   cd ec2-bench
   ```

2. 必要なPythonパッケージをインストールします：
   ```
   pip install -r requirements.txt
   ```

3. AWS CLIが、EC2インスタンス、セキュリティグループ、IAMロールを作成および管理するために必要な権限で設定されていることを確認してください。

## 使用方法

基本的な使用方法：

```
python ec2_bench.py --region <AWSリージョン> --vpc-id <VPC-ID> --instance-types <インスタンスタイプ1> <インスタンスタイプ2> ...
```

例：

```
python ec2_bench.py --region ap-northeast-1 --vpc-id vpc-12345678 --instance-types t3.micro t3a.micro t3g.micro
```

より複雑なシナリオの例：

```
python ec2_bench.py --region ap-northeast-1 --vpc-id vpc-12345678 --security-group sg-87654321 --instance-profile myprofile --instance-types c5.large m5.large --scripts "custom_benchmark.sh" "another_test.sh"
```

### オプション引数

- `--security-group`: 既存のセキュリティグループIDを指定
- `--instance-profile`: 既存のIAMインスタンスプロファイルを指定
- `--scripts`: インスタンスで実行する追加のカスタムスクリプトを指定

## 出力と結果の解釈

スクリプトは`dist`ディレクトリに`performance_results.json`というJSONファイルを生成します。このファイルには、テストされた各インスタンスタイプのベンチマーク結果が含まれています。結果の解釈方法は以下の通りです：

1. **インスタンス情報**: コア数、メモリサイズ、CPUモデルなどのインスタンスの詳細情報。

2. **CPUテスト**: CPUのパフォーマンスを示します。比較のために"events per second"（1秒あたりのイベント数）に注目してください。

3. **メモリテスト**: メモリのパフォーマンスを示します。"transferred"（転送量）と1秒あたりの操作数が主要な指標です。

4. **ファイルI/Oテスト**: ディスクのパフォーマンスを示します。1秒あたりの読み書き操作数と転送データ量に注目してください。

5. **カスタムテスト**: カスタムスクリプトを追加した場合、その出力がここに含まれます。

### ChatGPTやClaude等を使用した結果の比較

`performance_results.json`ファイルの内容を使用して、ChatGPTやClaude等のAIアシスタントに比較分析を依頼することができます。以下のようなプロンプトを使用してください：

```
以下はEC2インスタンスタイプのパフォーマンステスト結果です。この結果を表形式で見やすくしてください。

[ここにperformance_results.jsonの内容をペースト]

```

このプロンプトを使用することで、AIアシスタントは各インスタンスタイプのパフォーマンスを詳細に分析し、比較表を生成します。これにより、異なるインスタンスタイプの性能特性をより簡単に理解し、特定のワークロードに最適なインスタンスタイプを選択するための洞察を得ることができます。

## 開発

このプロジェクトには、Visual Studio Code用のdevcontainer設定が含まれており、Python 3環境とAWS CLIがインストールされた環境をセットアップします。

## トラブルシューティング

- **InstanceLimitExceededエラー**: EC2インスタンスの制限に達した可能性があります。未使用のインスタンスを終了するか、AWSに制限の引き上げを要求してください。
- **容量不足エラー**: スポットインスタンスで発生する可能性があります。別のインスタンスタイプまたはアベイラビリティーゾーンを試してください。
- **権限拒否**: AWS CLIがEC2インスタンス、セキュリティグループ、IAMロールを作成および管理するための正しい権限で設定されていることを確認してください。

## 免責事項

このツールはEC2インスタンスを作成および終了します。関連するコストに注意し、使用後にリソースを確実にクリーンアップしてください。作者は、このツールの使用によって発生する意図しないAWS料金について責任を負いません。