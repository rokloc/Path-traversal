# パストラバーサル
攻撃者がWebアプリケーションに対してファイルパスを操作し、本来アクセスしてはいけないサーバーのファイルを読み取ったり操作したりする攻撃手法のこと

## どういう攻撃か
例えば、Webアプリでファイル名を指定してファイルを読み込むAPIがあったとする。

GET /files?name=report.pdf

本来はreport.pdfだけ読めるけど、攻撃者が

GET /files?name=../../../../etc/passwd

のように相対パスの../を使ってサーバーのディレクトリ構造を遡り、/etc/passwd（Linuxのユーザー情報ファイル）などのシステムファイルを読み込ませてしまう攻撃がパストラバーサル。

## 対策
アプリが意図していない場所のファイルにアクセスさせない
4つの対策 を組み合わせる必要がある。

### パスの正規化 & ベースディレクトリ制限
ユーザー入力からファイルパスを生成するときは、必ず以下の処理をする：

Path baseDir = Paths.get("/app/data").toAbsolutePath().normalize();
Path resolved = baseDir.resolve(userInput).normalize();

if (!resolved.startsWith(baseDir)) {
    throw new SecurityException("不正なパスです");
}

これにより、
../ でベースディレクトリの外に出ようとしても弾ける。
絶対パスやシンボリックリンクの悪用もある程度防げる。



### Spring Security で認可（誰がどのファイルを見ていいか）
例：ログイン済ユーザーだけ /files/** にアクセス可能にす
http
  .authorizeHttpRequests(auth -> auth
    .requestMatchers("/files/**").authenticated()
    .anyRequest().permitAll()
  );

さらに、ユーザーごとにファイルアクセス制御したいなら、アプリ側のサービスで認可ロジックを入れる：
if (!fileOwnedByUser(resolved, loggedInUser)) {
    throw new AccessDeniedException("権限がありません");
}



### ファイル名を直接渡さず、IDやトークンで管理（可能なら）
ユーザーにファイル名を直接扱わせると、ファイル構造がバレやすい。
理想的には、ファイルをIDで管理する設計にする：

GET /files/info?id=abc123
そのIDから安全にファイルパスを内部で解決する。

### CSRF/XSSなど他の攻撃と組み合わさないようにする

ファイルを読み込むAPIが POST を使う場合は、CSRFトークンが必要（Spring SecurityはデフォルトでON）
ファイル名などを画面に出すときは、XSS対策（エスケープ）も必要


例：安全なファイル情報取得エンドポイント（Spring MVC）

@RestController
@RequestMapping("/files")
public class FileController {

    private final Path baseDir = Paths.get("/app/data").toAbsolutePath().normalize();

    @GetMapping("/info")
    public ResponseEntity<?> fileInfo(@RequestParam("name") String filename,
                                      Authentication auth) {
        Path resolved = baseDir.resolve(filename).normalize();

        // パストラバーサル対策
        if (!resolved.startsWith(baseDir)) {
            return ResponseEntity.badRequest().body("Invalid path");
        }

        // 認可チェック（任意）
        if (!userHasAccess(resolved, auth)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        try {
            if (!Files.exists(resolved)) {
                return ResponseEntity.notFound().build();
            }

            BasicFileAttributes attr = Files.readAttributes(resolved, BasicFileAttributes.class);
            Map<String, Object> fileInfo = Map.of(
                "name", resolved.getFileName().toString(),
                "size", attr.size(),
                "lastModified", attr.lastModifiedTime().toString()
            );
            return ResponseEntity.ok(fileInfo);

        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private boolean userHasAccess(Path filePath, Authentication auth) {
        // 実装例：ファイル名にユーザーIDが含まれているかなど
        return true;
    }
}


Spring Security の構成例（SecurityConfig）
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/files/**").authenticated()
                .anyRequest().permitAll()
            )
            .csrf(Customizer.withDefaults()) // CSRF対策はPOSTがあるなら必須
            .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
